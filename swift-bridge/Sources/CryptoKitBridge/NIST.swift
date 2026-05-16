import Foundation

let CK_NIST_P256: Int32 = 1
let CK_NIST_P384: Int32 = 1 << 1
let CK_NIST_P521: Int32 = 1 << 2

@_cdecl("ck_nist_supported_curve_mask")
public func ck_nist_supported_curve_mask() -> Int32 {
    CK_NIST_P256 | CK_NIST_P384 | CK_NIST_P521
}
