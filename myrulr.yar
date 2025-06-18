rule ContainsTestFile
{
    meta:
        description = "Flags files containing the string 'This is a test file'"
        author = "Someone"
        date = "2025-05-02"

    strings:
        $a = "This is a test file"

    condition:
        $a
}
