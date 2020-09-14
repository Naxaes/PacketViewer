#include <cstdarg>         // va_start, va_end, va_list
#include <cstdlib>         // exit
#include <cstdio>          // fprintf, vsnprintf, size_t


#define ASSERT(expression, ...)                                                      \
{                                                                                    \
    if (!(expression))                                                               \
        PrintAssertion(#expression, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);  \
}

#define ERROR(...) PrintError(__FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)



void PrintAssertion(const char* expression, const char* file, const char* function, size_t line, const char* message, ...) // __attribute__ ((format (printf, 5, 6)))
{
    if (message[0] != '\0')
    {
        static const unsigned BUFFER_SIZE = 256;
        static char format_buffer[BUFFER_SIZE]  = { 0 };
        static char message_buffer[BUFFER_SIZE] = { 0 };

        va_list argptr;
        va_start(argptr, message);
        vsnprintf(format_buffer, BUFFER_SIZE, message, argptr);
        va_end(argptr);


        int index = 0;
        const char* character = format_buffer;
        while (*character != '\0' && index < BUFFER_SIZE-3)
        {
            if (*character == '\n' && (index != 0 && character[-1] != '\\'))
            {
                message_buffer[index++] = *character++;

                // Alignment
                message_buffer[index++] = '\t';
                message_buffer[index++] = '\t';            
            }
            else
            {
                message_buffer[index++] = *character++;
            }
        }
        message_buffer[index] = '\0';


        fprintf(stderr,
            "[ ASSERTION FAILED ]:\n"
                "\tExpression: %s\n"
                "\tFile:       %s\n"
                "\tFunction:   %s\n"
                "\tLine:       %zu\n"
                "\tMessage:\n"
                "\t\t%s\n",
            expression, file, function, line, message_buffer
        );
    }
    else
    {
        fprintf(stderr,
            "[ ASSERTION FAILED ]:\n"
                "\tExpression: %s\n"
                "\tFile:       %s\n"
                "\tFunction:   %s\n"
                "\tLine:       %zu\n",
            expression, file,  function, line
        );

    }


    exit(1);
}



void PrintError(const char* file, const char* function, size_t line, const char* message, ...) // __attribute__ ((format (printf, 5, 6)))
{
    if (message[0] != '\0')
    {
        static const unsigned BUFFER_SIZE = 256;
        static char format_buffer[BUFFER_SIZE]  = { 0 };
        static char message_buffer[BUFFER_SIZE] = { 0 };

        va_list argptr;
        va_start(argptr, message);
        vsnprintf(format_buffer, BUFFER_SIZE, message, argptr);
        va_end(argptr);


        int index = 0;
        const char* character = format_buffer;
        while (*character != '\0' && index < BUFFER_SIZE-3)
        {
            if (*character == '\n' && (index != 0 && character[-1] != '\\'))
            {
                message_buffer[index++] = *character++;

                // Alignment
                message_buffer[index++] = '\t';
                message_buffer[index++] = '\t';            
            }
            else
            {
                message_buffer[index++] = *character++;
            }
        }
        message_buffer[index] = '\0';


        fprintf(stderr,
            "[ ERROR ]:\n"
                "\tFile:       %s\n"
                "\tFunction:   %s\n"
                "\tLine:       %zu\n"
                "\tMessage:\n"
                "\t\t%s\n",
            file, function, line, message_buffer
        );
    }
    else
    {
        fprintf(stderr,
            "[ ERROR ]:\n"
                "\tFile:       %s\n"
                "\tFunction:   %s\n"
                "\tLine:       %zu\n",
            file,  function, line
        );

    }


    exit(1);
}
