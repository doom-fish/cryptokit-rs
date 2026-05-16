import Foundation

@_cdecl("ck_key_agreement_supported_algorithm_mask")
public func ck_key_agreement_supported_algorithm_mask() -> Int32 {
    1 | (1 << 1) | (1 << 2) | (1 << 3)
}
