using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal static class SyncSemanticHasher
{
    public static byte[] Compute(SyncOperation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendInt32(hash, (int)operation.Kind);
        AppendString(hash, operation.FieldKey);
        SyncOperationPayload payload = operation.Payload;
        AppendString(hash, payload.TextValue);
        AppendByte(hash, payload.BoolValue switch
        {
            true => 2,
            false => 1,
            null => 0,
        });
        AppendInt32(hash, payload.IntValue ?? int.MinValue);
        AppendInt64(hash, payload.DateValue?.UtcTicks ?? long.MinValue);
        AppendGuid(hash, payload.GuidValue);
        AppendGuid(hash, payload.SecondaryGuidValue);

        if (payload.Account is not null)
        {
            AppendString(hash, payload.Account.Issuer.Trim().ToUpperInvariant());
            AppendString(hash, payload.Account.AccountName.Trim().ToUpperInvariant());
            AppendByte(hash, payload.Account.Favourite ? (byte)1 : (byte)0);
            AppendInt32(hash, payload.Account.SortOrder);
            AppendInt64(hash, payload.Account.ArchivedAtUtc?.UtcTicks ?? long.MinValue);
        }

        if (payload.SecretVersion is not null)
        {
            hash.AppendData(payload.SecretVersion.Secret);
            AppendInt32(hash, (int)payload.SecretVersion.Algorithm);
            AppendInt32(hash, payload.SecretVersion.Digits);
            AppendInt32(hash, payload.SecretVersion.Period);
        }

        if (payload.HistoryEntry is not null)
        {
            if (operation.Kind != SyncOperationKind.DuplicateDecision)
            {
                AppendGuid(hash, payload.HistoryEntry.Id);
                AppendInt64(hash, payload.HistoryEntry.OccurredAtUtc.UtcTicks);
            }

            AppendInt32(hash, (int)payload.HistoryEntry.Action);
            AppendGuid(hash, payload.HistoryEntry.SecretVersionId);
            AppendGuid(hash, payload.HistoryEntry.PreviousSecretVersionId);
            AppendGuid(hash, payload.HistoryEntry.RelatedAccountId);
        }

        AppendGuid(hash, payload.ConflictId);
        AppendInt32(hash, payload.Resolution.HasValue
            ? (int)payload.Resolution.Value
            : -1);
        return hash.GetHashAndReset();
    }

    private static void AppendString(IncrementalHash hash, string? value)
    {
        byte[] bytes = value is null ? [] : Encoding.UTF8.GetBytes(value);
        try
        {
            AppendInt32(hash, value is null ? -1 : bytes.Length);
            hash.AppendData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void AppendGuid(IncrementalHash hash, Guid? value)
    {
        Span<byte> bytes = stackalloc byte[17];
        bytes[0] = value.HasValue ? (byte)1 : (byte)0;
        if (value.HasValue)
        {
            value.Value.TryWriteBytes(bytes[1..]);
        }

        hash.AppendData(bytes);
        CryptographicOperations.ZeroMemory(bytes);
    }

    private static void AppendInt32(IncrementalHash hash, int value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static void AppendInt64(IncrementalHash hash, long value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        hash.AppendData(bytes);
    }

    private static void AppendByte(IncrementalHash hash, byte value)
    {
        Span<byte> bytes = stackalloc byte[1];
        bytes[0] = value;
        hash.AppendData(bytes);
    }
}
