using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Xunit;
using static Xunit.Assert;

namespace TestAmsi
{
    public class Test
    {
        [Fact]
        public void TestWithLargeFile()
        {
            const long k = 1024;
            const long m = 1024 * k;
            const long fileSize = 21 * m;
            var c = new Random(42);
            var fileBuffer = new byte[fileSize];

            c.NextBytes(fileBuffer);
            Equal(AMSI_RESULT.AMSI_RESULT_CLEAN, ScanInternal(new MemoryStream(fileBuffer), "test.file.txt"));
        }

        private AMSI_RESULT ScanInternal(Stream streamToCheck, string fileName)
        {
            var scanner = (IAntiMalware)new CAntiMalware();
            var stream = new AmsiStream(streamToCheck, fileName);
            var result = scanner.Scan(stream, out AMSI_RESULT scanResult, out IAntiMalwareProvider _);

            if (result != (ulong)HResult.S_OK)
            {
                throw new InvalidOperationException($"Malware scan returned not OK: {result}");
            }

            return scanResult;
        }
    }

    public class AmsiStream : IAmsiStream
    {
        private readonly Stream _input;
        private readonly string _name;

        // there might be a better way to get an array containing bytes for NullPtr
        // but I do not know of it. Do notice that the array size will change from 32 to 64 bits.
        private static readonly byte[] _nullPtr = new byte[Marshal.SizeOf(IntPtr.Zero)];

        public AmsiStream(Stream input, string name)
        {
            _input = input ?? throw new ArgumentNullException(nameof(input));
            _name = name ?? throw new ArgumentNullException(nameof(name));

        }

        public int GetAttribute(AMSI_ATTRIBUTE attribute, int dataSize, byte[] data, out int retData)
        {
            const int E_NOTIMPL = unchecked((int)0x80004001);
            const int E_NOT_SUFFICIENT_BUFFER = unchecked((int)0x8007007A);

            byte[] bytes = { };
            int retValue = 0;

            switch (attribute)
            {

                case AMSI_ATTRIBUTE.AMSI_ATTRIBUTE_APP_NAME:
                    bytes = Encoding.Unicode.GetBytes("TestAmsi" + "\0");
                    break;
                case AMSI_ATTRIBUTE.AMSI_ATTRIBUTE_CONTENT_NAME:
                    bytes = Encoding.Unicode.GetBytes(_name + "\0");
                    break;
                case AMSI_ATTRIBUTE.AMSI_ATTRIBUTE_CONTENT_SIZE:
                    bytes = BitConverter.GetBytes((ulong)_input.Length);
                    break;
                case AMSI_ATTRIBUTE.AMSI_ATTRIBUTE_SESSION:
                    bytes = _nullPtr;
                    break;
                case AMSI_ATTRIBUTE.AMSI_ATTRIBUTE_CONTENT_ADDRESS:
                    //bytes = _nullPtr;
                    retValue = E_NOTIMPL;
                    break;
                default:
                    retValue = E_NOTIMPL;
                    break;
            }

            retData = 0;
            if (retValue == 0)
            {
                retData = bytes.Length;
                if (dataSize < bytes.Length)
                    return E_NOT_SUFFICIENT_BUFFER;

                Array.Copy(bytes, data, bytes.Length);
            }

            return retValue;

        }

        public int Read(long position, int size, byte[] buffer, out int readSize)
        {
            _input.Seek(position, SeekOrigin.Begin);
            readSize = _input.Read(buffer, 0, size);
            return 0;
        }
    }

    [Guid("82d29c2e-f062-44e6-b5c9-3d9a2f24a2df"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown), ComImport]
    public interface IAntiMalware
    {
        uint Scan([MarshalAs(UnmanagedType.Interface)] IAmsiStream stream, out AMSI_RESULT result, [MarshalAs(UnmanagedType.Interface)] out IAntiMalwareProvider provider);
        void CloseSession(ulong session);
    }

    [ComImport]
    [Guid("fdb00e52-a214-4aa1-8fba-4357bb0072ec")]
    [ComSourceInterfaces(typeof(IAntiMalware))]
    public class CAntiMalware
    {
    }

    [Guid("3e47f2e5-81d4-4d3b-897f-545096770373"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IAmsiStream
    {
        [PreserveSig]
        int GetAttribute(AMSI_ATTRIBUTE attribute, int dataSize, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] data, out int retData);
        [PreserveSig]
        int Read(long position, int size, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] buffer, out int readSize);
    }

    [Guid("b2cabfe3-fe04-42b1-a5df-08d483d4d125"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IAntiMalwareProvider
    {
        uint Scan([In, MarshalAs(UnmanagedType.Interface)] IAmsiStream stream, [Out] out AMSI_RESULT result);
        void CloseSession(ulong session);
        uint DisplayName(ref IntPtr displayName);
    }

    public enum AMSI_RESULT
    {
        AMSI_RESULT_CLEAN = 0,
        AMSI_RESULT_NOT_DETECTED = 1,
        AMSI_RESULT_BLOCKED_BY_ADMIN_START = 2,
        AMSI_RESULT_BLOCKED_BY_ADMIN_END = 32767,
        AMSI_RESULT_DETECTED = 32768
    }

    public enum AMSI_ATTRIBUTE
    {
        AMSI_ATTRIBUTE_APP_NAME = 0,
        AMSI_ATTRIBUTE_CONTENT_NAME = 1,
        AMSI_ATTRIBUTE_CONTENT_SIZE = 2,
        AMSI_ATTRIBUTE_CONTENT_ADDRESS = 3,
        AMSI_ATTRIBUTE_SESSION = 4,
        AMSI_ATTRIBUTE_REDIRECT_CHAIN_SIZE = 5,
        AMSI_ATTRIBUTE_REDIRECT_CHAIN_ADDRESS = 6,
        AMSI_ATTRIBUTE_ALL_SIZE = 7,
        AMSI_ATTRIBUTE_ALL_ADDRESS = 8,
        AMSI_ATTRIBUTE_QUIET = 9
    }


    [ComVisible(false)]
    public enum HResult : uint
    {
        S_OK = 0,
        S_FALSE = 1,
        ERROR_FILE_NOT_FOUND = 0x80070002,
        INET_E_SECURITY_PROBLEM = 0x800c000e,
        E_INVALIDARG = 0x80070057,
    }
}
