using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Infrastructure.GitHub;
using PersonalAuthenticator.Infrastructure.Serialization;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Tests;

internal static class ProtocolFixtureFactory
{
    internal const long RepositoryId = 1_234_567_890_123;
    internal const string FixturePassword = "fixture-sync-password";
    internal static readonly Guid VaultId =
        Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
    internal static readonly Guid GenerationId =
        Guid.Parse("10213243-5465-7687-98a9-bacbdcedfe0f");

    private static readonly Guid AccountId =
        Guid.Parse("20314253-6475-8697-a8b9-cadbecfd0e1f");
    private static readonly Guid ActiveSecretId =
        Guid.Parse("30415263-7485-96a7-b8c9-daebfc0d1e2f");
    private static readonly Guid CandidateSecretId =
        Guid.Parse("40516273-8495-a6b7-c8d9-eafb0c1d2e3f");
    private static readonly Guid HistoryId =
        Guid.Parse("50617283-94a5-b6c7-d8e9-fa0b1c2d3e4f");
    private static readonly Guid DeviceA =
        Guid.Parse("60718293-a4b5-c6d7-e8f9-0a1b2c3d4e5f");
    private static readonly Guid DeviceB =
        Guid.Parse("718293a4-b5c6-d7e8-f90a-1b2c3d4e5f60");
    private static readonly Guid FixtureConflictId =
        Guid.Parse("8293a4b5-c6d7-e8f9-0a1b-2c3d4e5f6071");
    private static readonly DateTimeOffset BaseTime =
        new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    public static async Task<ProtocolFixtureSet> BuildAsync(
        CancellationToken cancellationToken)
    {
        byte[] salt = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray();
        byte[] syncKey = await DeriveKeyAsync(
            FixturePassword,
            salt,
            cancellationToken);
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        var disposableOperations = new List<SyncOperation>();
        try
        {
            (VaultAccountV2 account, SecretVersionV2 activeSecret) =
                CreateAccountAndSecret();
            using (activeSecret)
            using (SecretVersionV2 candidateSecret = CreateCandidateSecret())
            {
                var history = new AccountHistoryEntryV2(
                    HistoryId,
                    AccountId,
                    AccountHistoryAction.SecretCandidateAdded,
                    BaseTime.AddMinutes(2),
                    CandidateSecretId,
                    ActiveSecretId,
                    relatedAccountId: null,
                    actorDeviceId: DeviceA);

                byte[] accountJson = V2RecordSerializer.SerializeAccount(account);
                byte[] secretJson =
                    V2RecordSerializer.SerializeSecretVersion(activeSecret);
                byte[] historyJson =
                    V2RecordSerializer.SerializeHistoryEntry(history);
                files.Add("records/account.json", accountJson);
                files.Add("records/secret-version.json", secretJson);
                files.Add("records/history.json", historyJson);

                IReadOnlyList<SyncOperation> operations = CreateOperations(
                    account,
                    activeSecret,
                    candidateSecret,
                    history);
                disposableOperations.AddRange(operations);

                using GitHubSyncConfiguration configuration =
                    CreateConfiguration(syncKey);
                var operationVectors = new List<object>(operations.Count);
                int payloadFlagUnion = 0;
                for (int index = 0; index < operations.Count; index++)
                {
                    SyncOperation operation = operations[index];
                    string slug = ToSlug(operation.Kind);
                    string operationPath = $"operations/{index:D2}-{slug}.bin";
                    string envelopePath = $"objects/{index:D2}-{slug}.pao";
                    byte[] serialized = SyncOperationSerializer.Serialize(operation);
                    byte[] envelope =
                        GitHubRemoteProtocol.EncryptOperation(configuration, operation);
                    files.Add(operationPath, serialized);
                    files.Add(envelopePath, envelope);
                    int payloadFlags = GetPayloadFlags(operation.Payload);
                    payloadFlagUnion |= payloadFlags;
                    operationVectors.Add(new
                    {
                        operation.Kind,
                        KindValue = (int)operation.Kind,
                        operation.FieldKey,
                        PayloadFlags = payloadFlags,
                        PayloadFlagsHex = $"0x{payloadFlags:X3}",
                        OperationId = operation.Id,
                        operation.DeviceId,
                        operation.DeviceSequence,
                        operation.LogicalClock,
                        OccurredAtUtcTicks = operation.OccurredAtUtc.UtcTicks,
                        operation.AccountId,
                        InputCausalParents = operation.CausalParents,
                        SerializedCausalParents =
                            operation.CausalParents.Order().ToArray(),
                        OperationFile = operationPath,
                        OperationSha256 = ToHex(SHA256.HashData(serialized)),
                        SemanticHash =
                            ToHex(SyncSemanticHasher.Compute(operation)),
                        EnvelopeFile = envelopePath,
                        EnvelopeSha256 = ToHex(SHA256.HashData(envelope)),
                        Envelope = ReadEnvelopeVector(envelope),
                    });
                }

                byte[] descriptorNonce =
                    Enumerable.Range(16, 12).Select(value => (byte)value).ToArray();
                byte[] verifier = CreateVerifier();
                byte[] verifierCiphertext = new byte[verifier.Length];
                byte[] verifierTag = new byte[16];
                try
                {
                    using var aes = new AesGcm(syncKey, verifierTag.Length);
                    aes.Encrypt(
                        descriptorNonce,
                        verifier,
                        verifierCiphertext,
                        verifierTag);
                    var descriptor = new GitHubRemoteDescriptor(
                        GitHubRemoteProtocol.ProtocolVersion,
                        [GitHubRemoteProtocol.RequiredFeature],
                        RepositoryId,
                        VaultId,
                        GenerationId,
                        Convert.ToBase64String(salt),
                        Convert.ToBase64String(descriptorNonce),
                        Convert.ToBase64String(verifierCiphertext),
                        Convert.ToBase64String(verifierTag));
                    files.Add(
                        "descriptor.json",
                        GitHubRemoteProtocol.SerializeDescriptor(descriptor));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(descriptorNonce);
                    CryptographicOperations.ZeroMemory(verifierCiphertext);
                    CryptographicOperations.ZeroMemory(verifierTag);
                }

                MergeVector merge = CreateMergeVector();
                var guidInputs = new[]
                {
                    Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
                    Guid.Parse("00112234-4455-6677-8899-aabbccddeeff"),
                    Guid.Parse("10112233-4455-6677-8899-aabbccddeeff"),
                    Guid.Parse("00112233-4456-6677-8899-aabbccddeeff"),
                };
                var manifest = new
                {
                    FixtureVersion = 1,
                    TestOnly = true,
                    Warning =
                        "Synthetic conformance data only. Never use these values as credentials or OTP seeds.",
                    Protocol = new
                    {
                        Version = GitHubRemoteProtocol.ProtocolVersion,
                        GitHubRemoteProtocol.RequiredFeature,
                        ObjectMagic = "PAVGHO01",
                        ObjectHeaderBytes = 84,
                        TagBytes = 16,
                        MaximumDecryptedOperationBytes =
                            SyncOperationSerializer.MaximumOperationBytes,
                        IntegerEncoding = "little-endian",
                        GuidEncoding = ".NET Guid.ToByteArray/TryWriteBytes",
                        TimestampEncoding = ".NET UTC ticks since 0001-01-01T00:00:00Z",
                        ParentOrdering = ".NET Guid.CompareTo",
                    },
                    Argon2id = new
                    {
                        Password = FixturePassword,
                        SaltBase64 = Convert.ToBase64String(salt),
                        MemoryKiB = 65_536,
                        Iterations = 3,
                        Parallelism = 2,
                        OutputBytes = 32,
                        OutputBase64 = Convert.ToBase64String(syncKey),
                    },
                    Verifier = new
                    {
                        RepositoryId,
                        VaultId,
                        GenerationId,
                        InputHex = ToHex(CreateVerifierInput()),
                        Sha256Hex = ToHex(verifier),
                    },
                    Descriptor = new
                    {
                        File = "descriptor.json",
                        Sha256Hex = ToHex(SHA256.HashData(files["descriptor.json"])),
                        PropertyNames = new[]
                        {
                            "ProtocolVersion",
                            "RequiredFeatures",
                            "RepositoryId",
                            "VaultId",
                            "RemoteGeneration",
                            "Salt",
                            "Nonce",
                            "VerifierCiphertext",
                            "VerifierTag",
                        },
                    },
                    DotNetGuidVectors = guidInputs.Select(value => new
                    {
                        Value = value,
                        ToByteArrayHex = ToHex(value.ToByteArray()),
                        TryWriteBytesHex = ToHex(WriteGuid(value)),
                    }),
                    DotNetGuidCompareOrder =
                        guidInputs.Order().Select(value => value.ToString()).ToArray(),
                    UtcTickVectors = new[]
                    {
                        new
                        {
                            Iso8601 = "0001-01-01T00:00:00.0000000+00:00",
                            UtcTicks = DateTimeOffset.MinValue.UtcTicks,
                        },
                        new
                        {
                            Iso8601 = BaseTime.ToString("O"),
                            BaseTime.UtcTicks,
                        },
                        new
                        {
                            Iso8601 = BaseTime.AddTicks(6_789).ToString("O"),
                            UtcTicks = BaseTime.AddTicks(6_789).UtcTicks,
                        },
                    },
                    NestedRecordJson = new[]
                    {
                        RecordVector("account", "records/account.json", accountJson),
                        RecordVector(
                            "secret-version",
                            "records/secret-version.json",
                            secretJson),
                        RecordVector("history", "records/history.json", historyJson),
                    },
                    FieldKeys = new[]
                    {
                        SyncFieldKeys.Existence,
                        SyncFieldKeys.Issuer,
                        SyncFieldKeys.AccountName,
                        SyncFieldKeys.Favourite,
                        SyncFieldKeys.SortOrder,
                        SyncFieldKeys.Archive,
                        SyncFieldKeys.SecretSet,
                        SyncFieldKeys.ActiveSecret,
                        SyncFieldKeys.History,
                        SyncFieldKeys.DuplicateDecision,
                        SyncFieldKeys.Purge,
                        SyncFieldKeys.Resolution,
                    },
                    PayloadFlagUnion = payloadFlagUnion,
                    PayloadFlagUnionHex = $"0x{payloadFlagUnion:X3}",
                    Operations = operationVectors,
                    ConflictAndMerge = merge,
                };
                files.Add(
                    "manifest.json",
                    JsonSerializer.SerializeToUtf8Bytes(
                        manifest,
                        ManifestJsonOptions));
                return new ProtocolFixtureSet(files, syncKey.ToArray());
            }
        }
        finally
        {
            foreach (SyncOperation operation in disposableOperations)
            {
                operation.Dispose();
            }

            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(syncKey);
        }
    }

    public static GitHubSyncConfiguration CreateConfiguration(byte[] syncKey) =>
        new(
            "Tester4Real",
            "authenticator-sync",
            "personal-authenticator-sync",
            ".personal-authenticator",
            RepositoryId,
            VaultId,
            GenerationId,
            syncKey.ToArray(),
            Enabled: true,
            BackgroundSyncEnabled: false,
            UploadsPaused: false,
            KnownBranchHead: null,
            KnownObjectHashes: [],
            VerifiedDeviceSequences: [],
            LastSuccessfulSyncAtUtc: null,
            RateLimitResetsAtUtc: null,
            LastError: null);

    private static IReadOnlyList<SyncOperation> CreateOperations(
        VaultAccountV2 account,
        SecretVersionV2 activeSecret,
        SecretVersionV2 candidateSecret,
        AccountHistoryEntryV2 history)
    {
        Guid[] ids = Enumerable.Range(1, 12)
            .Select(index => Guid.Parse($"9{index:D7}-1111-2222-3344-5566778899aa"))
            .ToArray();
        Guid[] multipleParents =
        [
            ids[0],
            Guid.Parse("f0000000-1111-2222-3344-5566778899aa"),
            Guid.Parse("0000000f-1111-2222-3344-5566778899aa"),
        ];
        return
        [
            Operation(
                ids[0],
                1,
                1,
                SyncOperationKind.AccountAdded,
                SyncFieldKeys.Existence,
                [],
                new SyncOperationPayload
                {
                    Account = CloneAccount(account),
                    SecretVersion = CloneSecret(activeSecret),
                }),
            Operation(
                ids[1],
                2,
                2,
                SyncOperationKind.IssuerChanged,
                SyncFieldKeys.Issuer,
                [ids[0]],
                new SyncOperationPayload { TextValue = "Fixture Updated" }),
            Operation(
                ids[2],
                3,
                3,
                SyncOperationKind.AccountNameChanged,
                SyncFieldKeys.AccountName,
                multipleParents,
                new SyncOperationPayload { TextValue = "alice+android@example.test" }),
            Operation(
                ids[3],
                4,
                4,
                SyncOperationKind.FavouriteChanged,
                SyncFieldKeys.Favourite,
                [ids[0]],
                new SyncOperationPayload { BoolValue = true }),
            Operation(
                ids[4],
                5,
                5,
                SyncOperationKind.SortOrderChanged,
                SyncFieldKeys.SortOrder,
                [ids[0]],
                new SyncOperationPayload { IntValue = 42 }),
            Operation(
                ids[5],
                6,
                6,
                SyncOperationKind.ArchiveChanged,
                SyncFieldKeys.Archive,
                [ids[0]],
                new SyncOperationPayload { DateValue = BaseTime.AddDays(1) }),
            Operation(
                ids[6],
                7,
                7,
                SyncOperationKind.SecretAdded,
                SyncFieldKeys.SecretSet,
                [ids[0]],
                new SyncOperationPayload
                {
                    SecretVersion = CloneSecret(candidateSecret),
                }),
            Operation(
                ids[7],
                8,
                8,
                SyncOperationKind.ActiveSecretChanged,
                SyncFieldKeys.ActiveSecret,
                [ids[6]],
                new SyncOperationPayload { GuidValue = CandidateSecretId }),
            Operation(
                ids[8],
                9,
                9,
                SyncOperationKind.HistoryAdded,
                $"{SyncFieldKeys.History}:{HistoryId:N}",
                [ids[0]],
                new SyncOperationPayload { HistoryEntry = CloneHistory(history) }),
            Operation(
                ids[9],
                10,
                10,
                SyncOperationKind.DuplicateDecision,
                SyncFieldKeys.DuplicateDecision,
                [ids[0]],
                new SyncOperationPayload
                {
                    SecondaryGuidValue = ActiveSecretId,
                    HistoryEntry = CloneHistory(history),
                }),
            Operation(
                ids[10],
                11,
                11,
                SyncOperationKind.Purged,
                SyncFieldKeys.Archive,
                [ids[0]],
                new SyncOperationPayload()),
            Operation(
                ids[11],
                12,
                12,
                SyncOperationKind.ConflictResolved,
                $"{SyncFieldKeys.Resolution}:{FixtureConflictId:N}",
                [ids[0]],
                new SyncOperationPayload
                {
                    ConflictId = FixtureConflictId,
                    Resolution = SyncConflictResolution.KeepBoth,
                }),
        ];
    }

    private static SyncOperation Operation(
        Guid id,
        long deviceSequence,
        long logicalClock,
        SyncOperationKind kind,
        string fieldKey,
        IReadOnlyList<Guid> parents,
        SyncOperationPayload payload) =>
        new(
            id,
            deviceSequence % 2 == 0 ? DeviceB : DeviceA,
            deviceSequence,
            logicalClock,
            BaseTime.AddTicks(logicalClock),
            AccountId,
            kind,
            fieldKey,
            parents,
            payload);

    private static MergeVector CreateMergeVector()
    {
        Guid addId = Guid.Parse("a0000000-1111-2222-3344-5566778899aa");
        Guid changeAId = Guid.Parse("a0000001-1111-2222-3344-5566778899aa");
        Guid changeBId = Guid.Parse("a0000002-1111-2222-3344-5566778899aa");
        (VaultAccountV2 account, SecretVersionV2 secret) =
            CreateAccountAndSecret();
        using (secret)
        {
            using SyncOperation add = new(
                addId,
                DeviceA,
                1,
                1,
                BaseTime,
                AccountId,
                SyncOperationKind.AccountAdded,
                SyncFieldKeys.Existence,
                [],
                new SyncOperationPayload
                {
                    Account = account,
                    SecretVersion = CloneSecret(secret),
                });
            using SyncOperation changeA = new(
                changeAId,
                DeviceA,
                2,
                2,
                BaseTime.AddSeconds(1),
                AccountId,
                SyncOperationKind.IssuerChanged,
                SyncFieldKeys.Issuer,
                [addId],
                new SyncOperationPayload { TextValue = "Fixture A" });
            using SyncOperation changeB = new(
                changeBId,
                DeviceB,
                1,
                2,
                BaseTime.AddSeconds(2),
                AccountId,
                SyncOperationKind.IssuerChanged,
                SyncFieldKeys.Issuer,
                [addId],
                new SyncOperationPayload { TextValue = "Fixture B" });
            var operations = new Dictionary<Guid, SyncOperation>
            {
                [changeB.Id] = changeB,
                [add.Id] = add,
                [changeA.Id] = changeA,
            };
            using var empty = new V2VaultSnapshot([], []);
            using SyncMergeResult result = SyncMergeEngine.Apply(
                empty,
                operations,
                new HashSet<Guid>(),
                new Dictionary<SyncFieldAddress, IReadOnlyList<SyncFieldHead>>(),
                [],
                new Dictionary<Guid, Guid>(),
                new Dictionary<Guid, Guid>());
            SyncConflictRecord conflict = result.Conflicts.Single();
            return new MergeVector(
                InputDictionaryOrder: operations.Keys.ToArray(),
                DeterministicApplyOrder:
                [
                    addId,
                    .. new[] { changeA, changeB }
                        .OrderBy(operation => operation.LogicalClock)
                        .ThenBy(operation => operation.DeviceId)
                        .ThenBy(operation => operation.DeviceSequence)
                        .ThenBy(operation => operation.Id)
                        .Select(operation => operation.Id),
                ],
                FinalIssuer: result.Accounts.Single().Issuer,
                ConflictId: conflict.Id,
                ConflictKind: conflict.Kind,
                ConflictFieldKey: conflict.FieldKey,
                ConflictOperationAId: conflict.OperationAId,
                ConflictOperationBId: conflict.OperationBId,
                AppliedOperationIds: result.AppliedOperationIds.Order().ToArray(),
                UnresolvedConflictCount: result.Conflicts.Count);
        }
    }

    private static (VaultAccountV2 Account, SecretVersionV2 Secret)
        CreateAccountAndSecret()
    {
        var account = new VaultAccountV2(
            AccountId,
            "Fixture",
            "alice@example.test",
            ActiveSecretId,
            favourite: true,
            sortOrder: 7,
            createdAtUtc: BaseTime.AddMinutes(-5),
            updatedAtUtc: BaseTime.AddMinutes(-4));
        var secret = new SecretVersionV2(
            ActiveSecretId,
            AccountId,
            Enumerable.Range(1, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha256,
            8,
            45,
            "otpauth://totp/Fixture%3Aalice%40example.test" +
            "?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU&issuer=Fixture" +
            "&algorithm=SHA256&digits=8&period=45",
            ProvisioningUriOrigin.Original,
            SecretVersionState.Active,
            BaseTime.AddMinutes(-5));
        return (account, secret);
    }

    private static SecretVersionV2 CreateCandidateSecret() =>
        new(
            CandidateSecretId,
            AccountId,
            Enumerable.Range(21, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha512,
            6,
            30,
            "otpauth://totp/Fixture%3Aalice%40example.test" +
            "?secret=CUKBOGAZDINRYHI6D4QCCIRDEQSSMJZIFE&issuer=Fixture" +
            "&algorithm=SHA512",
            ProvisioningUriOrigin.CanonicalGenerated,
            SecretVersionState.Candidate,
            BaseTime.AddMinutes(1));

    private static VaultAccountV2 CloneAccount(VaultAccountV2 account) =>
        new(
            account.Id,
            account.Issuer,
            account.AccountName,
            account.ActiveSecretVersionId,
            account.Favourite,
            account.SortOrder,
            account.CreatedAtUtc,
            account.UpdatedAtUtc,
            account.ArchivedAtUtc);

    private static SecretVersionV2 CloneSecret(SecretVersionV2 secret) =>
        new(
            secret.Id,
            secret.AccountId,
            secret.Secret,
            secret.Algorithm,
            secret.Digits,
            secret.Period,
            secret.ProvisioningUri,
            secret.ProvisioningUriOrigin,
            secret.State,
            secret.CreatedAtUtc,
            secret.RetiredAtUtc);

    private static AccountHistoryEntryV2 CloneHistory(
        AccountHistoryEntryV2 history) =>
        new(
            history.Id,
            history.AccountId,
            history.Action,
            history.OccurredAtUtc,
            history.SecretVersionId,
            history.PreviousSecretVersionId,
            history.RelatedAccountId,
            history.ActorDeviceId);

    private static async Task<byte[]> DeriveKeyAsync(
        string password,
        byte[] salt,
        CancellationToken cancellationToken)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var argon = new Argon2id(passwordBytes)
            {
                Salt = salt,
                MemorySize = 65_536,
                Iterations = 3,
                DegreeOfParallelism = 2,
            };
            byte[] result = await argon.GetBytesAsync(32);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] CreateVerifierInput()
    {
        byte[] input = new byte[40];
        BinaryPrimitives.WriteInt64LittleEndian(input.AsSpan(0, 8), RepositoryId);
        VaultId.TryWriteBytes(input.AsSpan(8, 16));
        GenerationId.TryWriteBytes(input.AsSpan(24, 16));
        return input;
    }

    private static byte[] CreateVerifier()
    {
        byte[] input = CreateVerifierInput();
        try
        {
            return SHA256.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static int GetPayloadFlags(SyncOperationPayload payload)
    {
        int flags = 0;
        flags |= payload.TextValue is null ? 0 : 1 << 0;
        flags |= payload.BoolValue.HasValue ? 1 << 1 : 0;
        flags |= payload.IntValue.HasValue ? 1 << 2 : 0;
        flags |= payload.DateValue.HasValue ? 1 << 3 : 0;
        flags |= payload.GuidValue.HasValue ? 1 << 4 : 0;
        flags |= payload.SecondaryGuidValue.HasValue ? 1 << 5 : 0;
        flags |= payload.Account is null ? 0 : 1 << 6;
        flags |= payload.SecretVersion is null ? 0 : 1 << 7;
        flags |= payload.HistoryEntry is null ? 0 : 1 << 8;
        flags |= payload.ConflictId.HasValue ? 1 << 9 : 0;
        flags |= payload.Resolution.HasValue ? 1 << 10 : 0;
        return flags;
    }

    private static object ReadEnvelopeVector(byte[] envelope) =>
        new
        {
            MagicAscii = Encoding.ASCII.GetString(envelope, 0, 8),
            Version =
                BinaryPrimitives.ReadUInt16LittleEndian(envelope.AsSpan(8, 2)),
            Flags =
                BinaryPrimitives.ReadUInt16LittleEndian(envelope.AsSpan(10, 2)),
            RepositoryId =
                BinaryPrimitives.ReadInt64LittleEndian(envelope.AsSpan(12, 8)),
            VaultId = new Guid(envelope.AsSpan(20, 16)),
            GenerationId = new Guid(envelope.AsSpan(36, 16)),
            ObjectId = new Guid(envelope.AsSpan(52, 16)),
            NonceHex = ToHex(envelope.AsSpan(68, 12)),
            PlaintextLength =
                BinaryPrimitives.ReadInt32LittleEndian(envelope.AsSpan(80, 4)),
            HeaderHex = ToHex(envelope.AsSpan(0, 84)),
            CiphertextHex =
                ToHex(envelope.AsSpan(84, envelope.Length - 84 - 16)),
            TagHex = ToHex(envelope.AsSpan(envelope.Length - 16, 16)),
        };

    private static object RecordVector(string kind, string path, byte[] bytes) =>
        new
        {
            Kind = kind,
            File = path,
            Utf8 = Encoding.UTF8.GetString(bytes),
            Sha256Hex = ToHex(SHA256.HashData(bytes)),
        };

    private static byte[] WriteGuid(Guid value)
    {
        byte[] bytes = new byte[16];
        value.TryWriteBytes(bytes);
        return bytes;
    }

    private static string ToHex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(bytes).ToLowerInvariant();

    private static string ToSlug(SyncOperationKind kind)
    {
        string name = kind.ToString();
        var result = new StringBuilder(name.Length + 4);
        for (int index = 0; index < name.Length; index++)
        {
            char value = name[index];
            if (index > 0 && char.IsUpper(value))
            {
                result.Append('-');
            }

            result.Append(char.ToLowerInvariant(value));
        }

        return result.ToString();
    }

    internal sealed record MergeVector(
        IReadOnlyList<Guid> InputDictionaryOrder,
        IReadOnlyList<Guid> DeterministicApplyOrder,
        string FinalIssuer,
        Guid ConflictId,
        SyncConflictKind ConflictKind,
        string ConflictFieldKey,
        Guid ConflictOperationAId,
        Guid ConflictOperationBId,
        IReadOnlyList<Guid> AppliedOperationIds,
        int UnresolvedConflictCount);
}

internal sealed class ProtocolFixtureSet : IDisposable
{
    public ProtocolFixtureSet(
        IReadOnlyDictionary<string, byte[]> files,
        byte[] syncKey)
    {
        Files = files;
        SyncKey = syncKey;
    }

    public IReadOnlyDictionary<string, byte[]> Files { get; }

    public byte[] SyncKey { get; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(SyncKey);
        foreach (byte[] bytes in Files.Values)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
