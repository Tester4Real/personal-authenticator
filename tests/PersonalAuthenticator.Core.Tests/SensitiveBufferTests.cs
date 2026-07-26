using System.Reflection;
using PersonalAuthenticator.Core.Security;

namespace PersonalAuthenticator.Core.Tests;

public sealed class SensitiveBufferTests
{
    [Fact]
    public void Dispose_ZeroesOwnedArray()
    {
        var buffer = new SensitiveBuffer([1, 2, 3, 4]);
        FieldInfo field = typeof(SensitiveBuffer).GetField("_buffer", BindingFlags.Instance | BindingFlags.NonPublic)!;
        byte[] owned = (byte[])field.GetValue(buffer)!;

        buffer.Dispose();

        Assert.All(owned, value => Assert.Equal(0, value));
        Assert.Throws<ObjectDisposedException>(() => buffer.Copy());
    }
}
