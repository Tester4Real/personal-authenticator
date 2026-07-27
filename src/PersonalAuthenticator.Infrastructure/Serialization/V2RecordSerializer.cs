using System.Security.Cryptography;
using System.Text.Json;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.Infrastructure.Serialization;

internal static class V2RecordSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        MaxDepth = 16,
    };

    public static byte[] SerializeAccount(VaultAccountV2 account)
    {
        ArgumentNullException.ThrowIfNull(account);
        return JsonSerializer.SerializeToUtf8Bytes(
            AccountRecordDto.FromDomain(account),
            Options);
    }

    public static VaultAccountV2 DeserializeAccount(
        ReadOnlySpan<byte> payload,
        Guid expectedAccountId)
    {
        AccountRecordDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<AccountRecordDto>(payload, Options);
        }
        catch (JsonException exception)
        {
            throw InvalidRecord("The encrypted v2 account record is corrupt.", exception);
        }

        if (dto is null || dto.SchemaVersion != 1 || dto.Id != expectedAccountId)
        {
            throw InvalidRecord("The encrypted v2 account record is invalid.");
        }

        try
        {
            return dto.ToDomain();
        }
        catch (Exception exception) when (
            exception is ArgumentException or
                InvalidOperationException)
        {
            throw InvalidRecord("The encrypted v2 account record is invalid.", exception);
        }
    }

    public static byte[] SerializeSecretVersion(SecretVersionV2 version)
    {
        ArgumentNullException.ThrowIfNull(version);
        var dto = SecretVersionRecordDto.FromDomain(version);
        try
        {
            return JsonSerializer.SerializeToUtf8Bytes(dto, Options);
        }
        finally
        {
            dto.ClearSecret();
        }
    }

    public static SecretVersionV2 DeserializeSecretVersion(
        ReadOnlySpan<byte> payload,
        Guid expectedVersionId,
        Guid expectedAccountId)
    {
        SecretVersionRecordDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<SecretVersionRecordDto>(payload, Options);
        }
        catch (JsonException exception)
        {
            throw InvalidRecord("The encrypted v2 secret-version record is corrupt.", exception);
        }

        if (dto is null ||
            dto.SchemaVersion != 1 ||
            dto.Id != expectedVersionId ||
            dto.AccountId != expectedAccountId ||
            dto.SecretBytes is null)
        {
            dto?.ClearSecret();
            throw InvalidRecord("The encrypted v2 secret-version record is invalid.");
        }

        try
        {
            return dto.ToDomain();
        }
        catch (Exception exception) when (
            exception is ArgumentException or
                InvalidOperationException)
        {
            throw InvalidRecord("The encrypted v2 secret-version record is invalid.", exception);
        }
        finally
        {
            dto.ClearSecret();
        }
    }

    public static byte[] SerializeHistoryEntry(AccountHistoryEntryV2 entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return JsonSerializer.SerializeToUtf8Bytes(
            HistoryRecordDto.FromDomain(entry),
            Options);
    }

    public static AccountHistoryEntryV2 DeserializeHistoryEntry(
        ReadOnlySpan<byte> payload,
        Guid expectedHistoryId,
        Guid expectedAccountId)
    {
        HistoryRecordDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<HistoryRecordDto>(payload, Options);
        }
        catch (JsonException exception)
        {
            throw InvalidRecord("The encrypted v2 account-history record is corrupt.", exception);
        }

        if (dto is null ||
            dto.SchemaVersion != 1 ||
            dto.Id != expectedHistoryId ||
            dto.AccountId != expectedAccountId)
        {
            throw InvalidRecord("The encrypted v2 account-history record is invalid.");
        }

        try
        {
            return dto.ToDomain();
        }
        catch (Exception exception) when (
            exception is ArgumentException or
                InvalidOperationException)
        {
            throw InvalidRecord("The encrypted v2 account-history record is invalid.", exception);
        }
    }

    private static SafeApplicationException InvalidRecord(
        string message,
        Exception? innerException = null) =>
        innerException is null
            ? new SafeApplicationException("VaultV2.InvalidRecord", message)
            : new SafeApplicationException("VaultV2.InvalidRecord", message, innerException);

    private sealed class AccountRecordDto
    {
        public int SchemaVersion { get; set; }

        public Guid Id { get; set; }

        public string? Issuer { get; set; }

        public string? AccountName { get; set; }

        public Guid ActiveSecretVersionId { get; set; }

        public bool Favourite { get; set; }

        public int SortOrder { get; set; }

        public DateTimeOffset CreatedAtUtc { get; set; }

        public DateTimeOffset UpdatedAtUtc { get; set; }

        public DateTimeOffset? ArchivedAtUtc { get; set; }

        public static AccountRecordDto FromDomain(VaultAccountV2 account) =>
            new()
            {
                SchemaVersion = 1,
                Id = account.Id,
                Issuer = account.Issuer,
                AccountName = account.AccountName,
                ActiveSecretVersionId = account.ActiveSecretVersionId,
                Favourite = account.Favourite,
                SortOrder = account.SortOrder,
                CreatedAtUtc = account.CreatedAtUtc,
                UpdatedAtUtc = account.UpdatedAtUtc,
                ArchivedAtUtc = account.ArchivedAtUtc,
            };

        public VaultAccountV2 ToDomain() =>
            new(
                Id,
                Issuer!,
                AccountName!,
                ActiveSecretVersionId,
                Favourite,
                SortOrder,
                CreatedAtUtc,
                UpdatedAtUtc,
                ArchivedAtUtc);
    }

    private sealed class SecretVersionRecordDto
    {
        public int SchemaVersion { get; set; }

        public Guid Id { get; set; }

        public Guid AccountId { get; set; }

        public byte[]? SecretBytes { get; set; }

        public TotpAlgorithm Algorithm { get; set; }

        public int Digits { get; set; }

        public int Period { get; set; }

        public string? ProvisioningUri { get; set; }

        public ProvisioningUriOrigin ProvisioningUriOrigin { get; set; }

        public SecretVersionState State { get; set; }

        public DateTimeOffset CreatedAtUtc { get; set; }

        public DateTimeOffset? RetiredAtUtc { get; set; }

        public static SecretVersionRecordDto FromDomain(SecretVersionV2 version) =>
            new()
            {
                SchemaVersion = 1,
                Id = version.Id,
                AccountId = version.AccountId,
                SecretBytes = version.Secret.ToArray(),
                Algorithm = version.Algorithm,
                Digits = version.Digits,
                Period = version.Period,
                ProvisioningUri = version.ProvisioningUri,
                ProvisioningUriOrigin = version.ProvisioningUriOrigin,
                State = version.State,
                CreatedAtUtc = version.CreatedAtUtc,
                RetiredAtUtc = version.RetiredAtUtc,
            };

        public SecretVersionV2 ToDomain() =>
            new(
                Id,
                AccountId,
                SecretBytes!,
                Algorithm,
                Digits,
                Period,
                ProvisioningUri!,
                ProvisioningUriOrigin,
                State,
                CreatedAtUtc,
                RetiredAtUtc);

        public void ClearSecret()
        {
            if (SecretBytes is null)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(SecretBytes);
            SecretBytes = null;
        }
    }

    private sealed class HistoryRecordDto
    {
        public int SchemaVersion { get; set; }

        public Guid Id { get; set; }

        public Guid AccountId { get; set; }

        public AccountHistoryAction Action { get; set; }

        public DateTimeOffset OccurredAtUtc { get; set; }

        public Guid? SecretVersionId { get; set; }

        public Guid? PreviousSecretVersionId { get; set; }

        public Guid? RelatedAccountId { get; set; }

        public Guid? ActorDeviceId { get; set; }

        public static HistoryRecordDto FromDomain(AccountHistoryEntryV2 entry) =>
            new()
            {
                SchemaVersion = 1,
                Id = entry.Id,
                AccountId = entry.AccountId,
                Action = entry.Action,
                OccurredAtUtc = entry.OccurredAtUtc,
                SecretVersionId = entry.SecretVersionId,
                PreviousSecretVersionId = entry.PreviousSecretVersionId,
                RelatedAccountId = entry.RelatedAccountId,
                ActorDeviceId = entry.ActorDeviceId,
            };

        public AccountHistoryEntryV2 ToDomain() =>
            new(
                Id,
                AccountId,
                Action,
                OccurredAtUtc,
                SecretVersionId,
                PreviousSecretVersionId,
                RelatedAccountId,
                ActorDeviceId);
    }
}
