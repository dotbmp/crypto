# Notes

ToDos:
- Finish up the algos
- Create a test framework in C usings the reference impls of the algos
- Define API for stuff like salting hashes etc.
- Structuring (Relocate ciphers / hashes)


* Folder Structure
    There are still some questions about this
    - I changed it for a more compact structure, more compatible with the collections system
    - Not sure if other hashes should be in the lib, or only crypto
    - Tests as a sub-package; convenient for end users to run tests
        - Should end users even be getting the tests
        - I like having them in one folder, works well with single file builds