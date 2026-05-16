import Foundation

let CK_SYMMETRIC_KEY_SIZE_128: Int32 = 1
let CK_SYMMETRIC_KEY_SIZE_192: Int32 = 1 << 1
let CK_SYMMETRIC_KEY_SIZE_256: Int32 = 1 << 2

@_cdecl("ck_symmetric_key_supported_size_mask")
public func ck_symmetric_key_supported_size_mask() -> Int32 {
    CK_SYMMETRIC_KEY_SIZE_128 | CK_SYMMETRIC_KEY_SIZE_192 | CK_SYMMETRIC_KEY_SIZE_256
}
