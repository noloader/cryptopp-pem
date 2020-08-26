// This piece of goodness performs EOL conversions from CR or LF to CRLF.
// It basically performs the work of unix2dos and mac2dos. It is needed
// because our OpenSSL keys are no longer conform to RFC 1421. I don't
// know when that happened.
//
// We don't use unix2dos and mac2dos on Travis because it means we have
// to install it using Apt or Brew. It is easier to build this toy program.

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

void ConvertEOL(const char* arg);

int main(int argc, char* argv[])
{
    try
    {
        for (int i=1; i<argc; ++i)
        {
            ConvertEOL(argv[i]);
        }
    }
    catch(const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        std::exit(1);
    }

    std::exit(0);
}

void ConvertEOL(const char* arg)
{
    std::string pem;

    // Process existing file
    {
        std::ifstream file(arg);

        int ch;
        while((ch = file.get()) != EOF)
        {
            switch (ch)
            {
                default:
                    pem += ch;
                    break;
                case '\n':
                    pem += "\r\n";
                    break;
                case '\r':
                    if (file.peek() == '\n')
                        ch = file.get(); // discard
                    pem += "\r\n";
                    break;
            }
        }
    }

    // Write new file
    {
        std::ofstream file(arg);
        file.write(pem.data(), pem.size());
    }
}
