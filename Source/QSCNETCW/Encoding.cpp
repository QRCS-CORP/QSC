#include "Encoding.h"
#include <vector>

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    // -- Base64 --

    bool Encoding::Base64Decode(array<Byte>^ output, size_t outputLength, String^ input, size_t inputLength)
    {
        bool res = false;

        if (output != nullptr && input != nullptr)
        {
            if (output->LongLength >= static_cast<long>(outputLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];

                IntPtr pinput = Marshal::StringToHGlobalAnsi(input);
                res = qsc_encoding_base64_decode(pinnedOut, outputLength, static_cast<char*>(pinput.ToPointer()), inputLength);
                Marshal::FreeHGlobal(pinput);
            }
        }

        return res;
    }

    size_t Encoding::Base64DecodedSize(String^ input, size_t length)
    {
        size_t val;

        val = 0;

        if (input != nullptr)
        {
            IntPtr pinput = Marshal::StringToHGlobalAnsi(input);
            val = qsc_encoding_base64_decoded_size(static_cast<char*>(pinput.ToPointer()), length);
            Marshal::FreeHGlobal(pinput);
        }

        return val;
    }

    bool Encoding::Base64Encode(String^% output, size_t outputCapacity, array<Byte>^ input, size_t inputLength)
    {
        bool res;

        res = false;

        if (input != nullptr && outputCapacity > 0)
        {
            if (input->LongLength >= static_cast<long>(inputLength))
            {
                pin_ptr<Byte> pinnedIn = &input[0];
                std::vector<char> buffer(outputCapacity, '\0');

                qsc_encoding_base64_encode(buffer.data(), buffer.size(), pinnedIn, inputLength);

                // Convert the C++ char buffer to a .NET string
                output = gcnew String(buffer.data());
                res = true;
            }
        }

        return res;
    }

    size_t Encoding::Base64EncodedSize(size_t length)
    {
        size_t val;

        val = qsc_encoding_base64_encoded_size(length);

        return val;
    }

    bool Encoding::Base64IsValidChar(char value)
    {
        bool res;

        res = false;

        res = qsc_encoding_base64_is_valid_char(value);

        return res;
    }

    // -- Hex --

    bool Encoding::HexDecode(String^ input, size_t inputLength, array<Byte>^ output, size_t outputLength, size_t% decodedLength)
    {
        bool res;

        res = false;
        decodedLength = 0;

        if (input != nullptr && output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(outputLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                size_t declen = 0;

                IntPtr pinput = Marshal::StringToHGlobalAnsi(input);
                res = qsc_encoding_hex_decode(static_cast<char*>(pinput.ToPointer()), inputLength, pinnedOut, outputLength, &declen);
                Marshal::FreeHGlobal(pinput);

                if (res == true)
                {
                    decodedLength = declen;
                }
            }
        }

        return res;
    }

    bool Encoding::HexEncode(array<Byte>^ input, size_t inputLength, String^% output, size_t outputCapacity)
    {
        bool res;

        res = false;

        if (input != nullptr && outputCapacity > 0)
        {
            if (input->LongLength >= static_cast<long>(inputLength))
            {
                pin_ptr<Byte> pinnedIn = &input[0];
                std::vector<char> buffer(outputCapacity, '\0');

                res = qsc_encoding_hex_encode(pinnedIn, inputLength, buffer.data(), buffer.size());

                if (res == true)
                {
                    output = gcnew String(buffer.data());
                }
            }
        }

        return res;
    }

    // -- PEM --

    bool Encoding::PemDecode(String^ input, array<Byte>^ output, size_t outputLength, size_t% decodedLength)
    {
        bool res;

        res = false;
        decodedLength = 0;

        if (input != nullptr && output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(outputLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                size_t declen = 0;
                IntPtr pinput = Marshal::StringToHGlobalAnsi(input);
                res = qsc_encoding_pem_decode(static_cast<char*>(pinput.ToPointer()), pinnedOut, outputLength, &declen);
                Marshal::FreeHGlobal(pinput);

                if (res == true)
                {
                    decodedLength = declen;
                }
            }
        }

        return res;
    }

    bool Encoding::PemEncode(String^ label, String^% output, size_t outputCapacity, array<Byte>^ data, size_t dataLength)
    {
        bool res;

        res = false;

        if (label != nullptr && data != nullptr && outputCapacity > 0)
        {
            if (data->LongLength >= static_cast<long>(dataLength))
            {
                IntPtr plabel = Marshal::StringToHGlobalAnsi(label);
                pin_ptr<Byte> pinnedData = &data[0];
                std::vector<char> buffer(outputCapacity, '\0');

                res = qsc_encoding_pem_encode(static_cast<char*>(plabel.ToPointer()), buffer.data(), buffer.size(), pinnedData, dataLength);
                Marshal::FreeHGlobal(plabel);

                if (res == true)
                {
                    output = gcnew String(buffer.data());
                }
            }
        }

        return res;
    }

    // -- BER/DER --

    IntPtr Encoding::BERDecodeElement(array<Byte>^ buffer, size_t bufferLength, size_t% consumed)
    {
        IntPtr res;

        res = IntPtr::Zero;
        consumed = 0;

        if (buffer != nullptr)
        {
            if (buffer->LongLength >= static_cast<long>(bufferLength))
            {
                pin_ptr<Byte> pinnedBuf = &buffer[0];
                size_t used = 0;
                qsc_encoding_ber_element* elem = qsc_encoding_ber_decode_element(pinnedBuf, bufferLength, &used);
                consumed = used;
                res = IntPtr(elem);
            }
        }

        return res;
    }

    size_t Encoding::BEREncodeElement(IntPtr elementPtr, array<Byte>^ output, size_t outputLength)
    {
        size_t written;

        written = 0;

        if (elementPtr != IntPtr::Zero && output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(outputLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                qsc_encoding_ber_element* elem = reinterpret_cast<qsc_encoding_ber_element*>(elementPtr.ToPointer());
                size_t w = qsc_encoding_ber_encode_element(elem, pinnedOut, outputLength);
                written = w;
            }
        }

        return written;
    }

    IntPtr Encoding::DERDecodeElement(array<Byte>^ buffer, size_t bufferLength, size_t% consumed)
    {
        IntPtr res;

        res = IntPtr::Zero;
        consumed = 0;

        if (buffer != nullptr && buffer->LongLength >= static_cast<long>(bufferLength))
        {
            pin_ptr<Byte> pinnedBuf = &buffer[0];
            size_t used = 0;
            qsc_encoding_ber_element* elem = qsc_encoding_der_decode_element(pinnedBuf, bufferLength, &used);
            consumed = used;
            res = IntPtr(elem);
        }

        return res;
    }

    size_t Encoding::DEREncodeElement(IntPtr elementPtr, array<Byte>^ output, size_t outputLength)
    {
        size_t written;

        written = 0;

        if (elementPtr != IntPtr::Zero && output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(outputLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                qsc_encoding_ber_element* elem = reinterpret_cast<qsc_encoding_ber_element*>(elementPtr.ToPointer());
                size_t w = qsc_encoding_der_encode_element(elem, pinnedOut, outputLength);
                written = w;
            }
        }

        return written;
    }

    void Encoding::FreeBERElement(IntPtr elementPtr)
    {
        if (elementPtr != IntPtr::Zero)
        {
            qsc_encoding_ber_element* elem = reinterpret_cast<qsc_encoding_ber_element*>(elementPtr.ToPointer());
            encoding_ber_free_element(elem);
        }
    }
}