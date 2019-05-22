package crypto

import "core:mem"
import "core:os"


hash_file :: proc{hash_file_array, hash_file_slice_in, hash_file_slice_out};

hash_file_array :: proc(file_name: string, fn: proc "contextless" (data: []byte) -> [$N]byte) -> ([N]byte, bool) {
    if bytes, ok := os.read_entire_file(file_name); ok {
        return fn(bytes), true;
    }
    return ---, false;
}
hash_file_slice_in :: proc(hash: []byte, file_name: string, fn: proc "contextless" (data, hash: []byte)) -> bool {
    if bytes, ok := os.read_entire_file(file_name); ok {
        fn(bytes, hash);
        return true;
    }
    return false;
}
hash_file_slice_out :: proc(file_name: string, fn: proc "contextless" (data: []byte) -> []byte) -> ([]byte, bool) {
    if bytes, ok := os.read_entire_file(file_name); ok {
        return fn(bytes), true;
    }
    return ---, false;
}


compare_bytes :: proc{compare_bytes_array, compare_bytes_slice_in, compare_bytes_slice_out};

compare_bytes_array :: proc(data1, data2: []byte, fn: proc "contextless" (data: []byte) -> [$N]byte) -> bool {
    if len(data1) != len(data2) do return false;
    
    hash1 := fn(data1);
    hash2 := fn(data2);
    
    return mem.compare(hash1[:], hash2[:]) == 0;
}
// @note(bp): is this really necessary?
compare_bytes_slice_in :: proc(hash1, hash2, data1, data2: []byte, fn: proc "contextless" (data, hash: []byte)) -> bool {
    if len(data1) != len(data2) do return false;
    
    fn(data1, hash1);
    fn(data2, hash2);
    
    return mem.compare(hash1, hash2) == 0;
}
compare_bytes_slice_out :: proc(data1, data2: []byte, fn: proc "contextless" (data: []byte) -> []byte) -> bool {
    if len(data1) != len(data2) do return false;
    
    hash1 := fn(data1);
    hash2 := fn(data2);
    defer delete(hash1);
    defer delete(hash2);
    
    return mem.compare(hash1, hash2) == 0;
}


compare_files :: proc{compare_files_array, compare_files_slice_in, compare_files_slice_out};

compare_files_array :: proc(file1, file2: string, fn: proc "contextless" (data: []byte) -> [$N]byte) -> (res: bool, ok: bool) {
    hash1, hash2: [N]byte = ---, ---;

    hash1, ok = hash_file_array(file1, fn);
    if !ok do return ---, false;
    hash2, ok = hash_file_array(file2, fn);
    if !ok do return ---, false;

    return mem.compare(hash1[:], hash2[:]) == 0, true;
}
compare_files_slice_in :: proc(hash1, hash2: []byte, file1, file2: string, fn: proc "contextless" (data, hash: []byte)) -> (res: bool, ok: bool) {
    if !hash_file_slice_in(hash1, file1, fn) do return ---, false;
    if !hash_file_slice_in(hash2, file2, fn) do return ---, false;

    return mem.compare(hash1, hash2) == 0, true;
}
compare_files_slice_out :: proc(file1, file2: string, fn: proc "contextless" (data: []byte) -> []byte) -> (res: bool, ok: bool) {
    hash1, hash2: []byte = ---, ---;

    hash1, ok = hash_file_slice_out(file1, fn);
    if !ok do return ---, false;
    hash2, ok = hash_file_slice_out(file2, fn);
    if !ok do return ---, false;

    return mem.compare(hash1, hash2) == 0, true;
}
