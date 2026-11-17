using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace EasyPatch.Tests.Integration;

/// <summary>
/// A WebAuthn authenticator in software, answering <c>navigator.credentials.create()</c> / <c>get()</c> options the way a browser
/// and a security key would: an ECDSA P-256 (ES256) key, attestation format "none", responses in the browser's JSON form.
/// </summary>
public sealed class SoftwareAuthenticator : IDisposable
{
    public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(32);
    public uint SignCount { get; set; }
    public byte[]? UserHandle { get; set; }

    /// <summary>The relying party the authenticator signs for (its SHA-256 goes into the authenticator data).</summary>
    public string RpId { get; set; } = new Uri(EasyPatchApiFactory.PublicUrl).Host;

    /// <summary>The page origin the "browser" reports in the client data.</summary>
    public string Origin { get; set; } = EasyPatchApiFactory.PublicUrl;

    public static string B64(byte[] bytes) => Base64Url.EncodeToString(bytes);

    public static byte[] FromB64(string value) => Base64Url.DecodeFromChars(value);

    /// <summary>Registers this credential. <paramref name="residentKey"/> is what the browser reports in the credProps extension.</summary>
    public JsonObject Create(JsonElement options, bool userVerified = true, bool? residentKey = null)
    {
        UserHandle = FromB64(options.GetProperty("user").GetProperty("id").GetString()!);
        var clientData = ClientData("webauthn.create", options.GetProperty("challenge").GetString()!);
        var cbor = new CborWriter(CborConformanceMode.Ctap2Canonical);
        cbor.WriteStartMap(3);
        cbor.WriteTextString("fmt");
        cbor.WriteTextString("none");
        cbor.WriteTextString("attStmt");
        cbor.WriteStartMap(0);
        cbor.WriteEndMap();
        cbor.WriteTextString("authData");
        cbor.WriteByteString(AuthenticatorData(userVerified, attested: true));
        cbor.WriteEndMap();

        var extensions = new JsonObject();
        if (residentKey is { } rk)
        {
            extensions["credProps"] = new JsonObject { ["rk"] = rk };
        }

        return new JsonObject
        {
            ["id"] = B64(CredentialId),
            ["rawId"] = B64(CredentialId),
            ["type"] = "public-key",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = B64(clientData),
                ["attestationObject"] = B64(cbor.Encode()),
                ["transports"] = new JsonArray("usb"),
            },
            ["clientExtensionResults"] = extensions,
        };
    }

    /// <summary>Signs an assertion for <paramref name="options"/>. A passkey returns the user handle; a security key used as a second
    /// factor usually does not.</summary>
    public JsonObject Get(JsonElement options, bool userVerified = false, bool includeUserHandle = true)
    {
        SignCount++;
        var clientData = ClientData("webauthn.get", options.GetProperty("challenge").GetString()!);
        var authData = AuthenticatorData(userVerified, attested: false);
        var signature = Key.SignData([.. authData, .. SHA256.HashData(clientData)], HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var response = new JsonObject
        {
            ["clientDataJSON"] = B64(clientData),
            ["authenticatorData"] = B64(authData),
            ["signature"] = B64(signature),
        };
        if (includeUserHandle && UserHandle is not null)
        {
            response["userHandle"] = B64(UserHandle);
        }

        return new JsonObject
        {
            ["id"] = B64(CredentialId),
            ["rawId"] = B64(CredentialId),
            ["type"] = "public-key",
            ["response"] = response,
            ["clientExtensionResults"] = new JsonObject(),
        };
    }

    public void Dispose() => Key.Dispose();

    private byte[] ClientData(string type, string challenge) =>
        JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> { ["type"] = type, ["challenge"] = challenge, ["origin"] = Origin, ["crossOrigin"] = false });

    private byte[] AuthenticatorData(bool userVerified, bool attested)
    {
        using var data = new MemoryStream();
        data.Write(SHA256.HashData(Encoding.UTF8.GetBytes(RpId)));
        data.WriteByte((byte)(0x01 /* UP */ | (userVerified ? 0x04 : 0) /* UV */ | (attested ? 0x40 : 0) /* AT */));
        var counter = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(counter, SignCount);
        data.Write(counter);
        if (attested)
        {
            data.Write(new byte[16]); // AAGUID: not disclosed
            var length = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)CredentialId.Length);
            data.Write(length);
            data.Write(CredentialId);
            data.Write(CosePublicKey());
        }

        return data.ToArray();
    }

    private byte[] CosePublicKey()
    {
        var point = Key.ExportParameters(includePrivateParameters: false).Q;
        var cbor = new CborWriter(CborConformanceMode.Ctap2Canonical);
        cbor.WriteStartMap(5);
        cbor.WriteInt32(1); // kty
        cbor.WriteInt32(2); // EC2
        cbor.WriteInt32(3); // alg
        cbor.WriteInt32(-7); // ES256
        cbor.WriteInt32(-1); // crv
        cbor.WriteInt32(1); // P-256
        cbor.WriteInt32(-2); // x
        cbor.WriteByteString(point.X!);
        cbor.WriteInt32(-3); // y
        cbor.WriteByteString(point.Y!);
        cbor.WriteEndMap();
        return cbor.Encode();
    }
}
