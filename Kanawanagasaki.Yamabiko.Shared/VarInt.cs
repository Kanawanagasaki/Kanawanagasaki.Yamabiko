namespace Kanawanagasaki.Yamabiko.Shared;

public readonly struct VarInt : IEquatable<VarInt>, IComparable<VarInt>
{
    private readonly long _value;

    public VarInt(long value)
    {
        _value = value;
    }

    public override string ToString() => _value.ToString();
    public override bool Equals(object? obj) => obj is VarInt other && Equals(other);
    public override int GetHashCode() => _value.GetHashCode();

    public bool Equals(VarInt other) => _value == other._value;
    public int CompareTo(VarInt other) => _value.CompareTo(other._value);

    public static implicit operator long(VarInt varint) => varint._value;
    public static implicit operator VarInt(long value) => new VarInt(value);

    public static explicit operator ulong(VarInt varint) => (ulong)varint._value;
    public static explicit operator VarInt(ulong value) => new VarInt((long)value);

    public static explicit operator int(VarInt varint) => (int)varint._value;
    public static explicit operator VarInt(int value) => new VarInt(value);

    public static explicit operator uint(VarInt varint) => (uint)varint._value;
    public static explicit operator VarInt(uint value) => new VarInt(value);

    public static explicit operator short(VarInt varint) => (short)varint._value;
    public static explicit operator VarInt(short value) => new VarInt(value);

    public static explicit operator ushort(VarInt varint) => (ushort)varint._value;
    public static explicit operator VarInt(ushort value) => new VarInt(value);

    public static explicit operator sbyte(VarInt varint) => (sbyte)varint._value;
    public static explicit operator VarInt(sbyte value) => new VarInt(value);

    public static explicit operator byte(VarInt varint) => (byte)varint._value;
    public static explicit operator VarInt(byte value) => new VarInt(value);
}
