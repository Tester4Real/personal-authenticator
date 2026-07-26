using System.Security.Cryptography;
using System.Text.Json;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.Infrastructure.Serialization;

internal static class VaultJsonSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        MaxDepth = 16,
    };

    public static byte[] Serialize(IReadOnlyCollection<TotpAccount> accounts)
    {
        var payload = new VaultPayloadDto
        {
            FormatVersion = 1,
            Accounts = new List<VaultAccountDto>(accounts.Count),
        };

        try
        {
            foreach (TotpAccount account in accounts)
            {
                payload.Accounts.Add(VaultAccountDto.FromDomain(account));
            }

            return JsonSerializer.SerializeToUtf8Bytes(payload, Options);
        }
        finally
        {
            payload.ClearSecrets();
        }
    }

    public static IReadOnlyList<TotpAccount> Deserialize(ReadOnlySpan<byte> json)
    {
        VaultPayloadDto? payload;
        try
        {
            payload = JsonSerializer.Deserialize<VaultPayloadDto>(json, Options);
        }
        catch (JsonException exception)
        {
            throw new SafeApplicationException("Vault.InvalidPayload", "The vault payload is corrupt.", exception);
        }

        if (payload is null || payload.FormatVersion != 1 || payload.Accounts is null)
        {
            throw new SafeApplicationException("Vault.InvalidPayload", "The vault payload version is not supported.");
        }

        var accounts = new List<TotpAccount>(payload.Accounts.Count);
        try
        {
            foreach (VaultAccountDto item in payload.Accounts)
            {
                item.Validate();
                accounts.Add(item.ToDomain());
            }

            return accounts;
        }
        catch
        {
            foreach (TotpAccount account in accounts)
            {
                account.Dispose();
            }

            throw;
        }
        finally
        {
            payload.ClearSecrets();
        }
    }

    private sealed class VaultPayloadDto
    {
        public int FormatVersion { get; set; }

        public List<VaultAccountDto>? Accounts { get; set; }

        public void ClearSecrets()
        {
            if (Accounts is null)
            {
                return;
            }

            foreach (VaultAccountDto account in Accounts)
            {
                account.ClearSecret();
            }
        }
    }

    private sealed class VaultAccountDto
    {
        public Guid Id { get; set; }

        public string? Issuer { get; set; }

        public string? AccountName { get; set; }

        public byte[]? SecretBytes { get; set; }

        public TotpAlgorithm Algorithm { get; set; }

        public int Digits { get; set; }

        public int Period { get; set; }

        public bool Favourite { get; set; }

        public int SortOrder { get; set; }

        public DateTimeOffset CreatedAtUtc { get; set; }

        public DateTimeOffset UpdatedAtUtc { get; set; }

        public static VaultAccountDto FromDomain(TotpAccount account) =>
            new()
            {
                Id = account.Id,
                Issuer = account.Issuer,
                AccountName = account.AccountName,
                SecretBytes = account.Secret.ToArray(),
                Algorithm = account.Algorithm,
                Digits = account.Digits,
                Period = account.Period,
                Favourite = account.Favourite,
                SortOrder = account.SortOrder,
                CreatedAtUtc = account.CreatedAtUtc,
                UpdatedAtUtc = account.UpdatedAtUtc,
            };

        public TotpAccount ToDomain() =>
            new(
                Id,
                Issuer!,
                AccountName!,
                SecretBytes!,
                Algorithm,
                Digits,
                Period,
                Favourite,
                SortOrder,
                CreatedAtUtc,
                UpdatedAtUtc);

        public void Validate()
        {
            if (Id == Guid.Empty ||
                string.IsNullOrWhiteSpace(Issuer) ||
                string.IsNullOrWhiteSpace(AccountName) ||
                SecretBytes is null)
            {
                throw new SafeApplicationException("Vault.InvalidAccount", "The vault contains an invalid account.");
            }
        }

        public void ClearSecret()
        {
            if (SecretBytes is not null)
            {
                CryptographicOperations.ZeroMemory(SecretBytes);
                SecretBytes = null;
            }
        }
    }
}
