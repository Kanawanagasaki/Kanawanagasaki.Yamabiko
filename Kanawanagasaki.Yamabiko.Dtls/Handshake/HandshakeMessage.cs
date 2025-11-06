namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using System.Buffers;

internal sealed class HandshakeMessage
{
    internal IHandshake? Handshake { get; private set; }

    internal ushort SequenceNumber { get; }

    private readonly List<HandshakeFragment> _fragments = [];

    internal HandshakeMessage(IHandshake handshake, ushort sequenceNum)
    {
        Handshake = handshake;
        SequenceNumber = sequenceNum;
    }

    internal HandshakeMessage(HandshakeFragment firstFragment)
    {
        _fragments.Add(firstFragment);
        SequenceNumber = firstFragment.SequenceNumber;
        ParseFragments();
    }

    internal void AddFragment(HandshakeFragment fragment)
    {
        if (Handshake is not null)
            throw new InvalidOperationException("Handshake already assembled");

        if (SequenceNumber != fragment.SequenceNumber)
            throw new ArgumentException("Mismatched sequence number", nameof(fragment));

        if (0 < _fragments.Count && _fragments[0].TotalLength != fragment.TotalLength)
            throw new ArgumentException("Mismatched total length", nameof(fragment));

        _fragments.Add(fragment);
        ParseFragments();
    }

    private void ParseFragments()
    {
        CombineFragments();

        if (_fragments.Count != 1)
            return;

        var fragment = _fragments[0];

        if (fragment.FragmentOffset != 0)
            return;
        if (fragment.TotalLength < fragment.FragmentLength)
            throw new FormatException("Fragment length was greater than total length");
        if (fragment.FragmentLength != fragment.TotalLength)
            return;

        Handshake = IHandshake.Parse(fragment.Type, fragment.Fragment);
    }

    private void CombineFragments()
    {
        _fragments.Sort((a, b) => a.FragmentOffset.CompareTo(b.FragmentOffset));
        for (int i = 0; i < _fragments.Count - 1; i++)
        {
            var f1 = _fragments[i];
            var f2 = _fragments[i + 1];

            if (f1.FragmentOffset + f1.FragmentLength < f2.FragmentOffset)
                continue;

            var startInc = f1.FragmentOffset;
            var endExc = Math.Max(f1.FragmentOffset + f1.FragmentLength, f2.FragmentOffset + f2.FragmentLength);
            var length = endExc - startInc;
            var buffer = new byte[length];
            f1.Fragment.CopyTo(buffer.AsSpan(f1.FragmentOffset - startInc));
            f2.Fragment.CopyTo(buffer.AsSpan(f2.FragmentOffset - startInc));

            _fragments.RemoveAt(i + 1);
            _fragments[i] = new HandshakeFragment(buffer)
            {
                Type = f1.Type,
                TotalLength = f1.TotalLength,
                SequenceNumber = SequenceNumber,
                FragmentOffset = startInc
            };
            i--;
        }
    }

    internal HandshakeFragment[] GetFragments(int fragmentMaxLength)
    {
        if (Handshake is null)
            throw new NullReferenceException($"{nameof(Handshake)} was null");

        if (fragmentMaxLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(fragmentMaxLength), "fragmentMaxLength must be greater than 0");

        var length = Handshake.Length();
        if (0xFFFFFF < length)
            throw new FormatException("Handshake length exceeds 24-bit");

        var count = length / fragmentMaxLength + (length % fragmentMaxLength == 0 ? 0 : 1);
        var fragments = new HandshakeFragment[count];

        var rentedArray = ArrayPool<byte>.Shared.Rent(length);

        try
        {
            var buffer = rentedArray.AsSpan(0, length);
            Handshake.Write(buffer);

            for (int i = 0; i < fragments.Length; i++)
            {
                var fragmentOffset = i * fragmentMaxLength;
                var fragmentLength = Math.Min(fragmentMaxLength, length - fragmentOffset);
                if (0xFFFFFF < fragmentLength)
                    throw new FormatException("Fragment length exceeds 24-bit");

                fragments[i] = new HandshakeFragment(buffer.Slice(fragmentOffset, fragmentLength).ToArray())
                {
                    Type = Handshake.Type,
                    TotalLength = length,
                    SequenceNumber = SequenceNumber,
                    FragmentOffset = fragmentOffset
                };
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedArray);
        }

        if(fragments.Length == 1 && _fragments.Count != 1)
        {
            _fragments.Add(fragments[0]);
            CombineFragments();
        }

        return fragments;
    }

    internal HandshakeFragment GetFragment()
    {
        if (Handshake is null)
            throw new NullReferenceException("Handshake hasn't been assembled yet");

        if (_fragments.Count == 1 && _fragments[0].FragmentLength == _fragments[0].TotalLength)
            return _fragments[0];

        var fragments = GetFragments(0xFFFFFF);
        if (fragments.Length != 1)
            throw new Exception("Failed to get write message as one fragment");

        return fragments[0];
    }
}
