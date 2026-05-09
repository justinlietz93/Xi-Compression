# Xi Codec v0 Compression Test
| file | raw bytes | zlib9 bytes | xi codec bytes | xi ratio raw/codec | xi minus zlib bytes | modes | roundtrip |
|---|---:|---:|---:|---:|---:|---|---|
| mock_text_repeated.txt | 417272 | 12461 | 28088 | 14.856 | 15627 | raw_zlib:102 | True |
| mock_xi_native.bin | 262144 | 34230 | 388 | 675.629 | -33842 | xi_direct_no_payload:64 | True |
| mock_xi_sparse_residual.bin | 262144 | 34727 | 6282 | 41.729 | -28445 | xi_xor_residual_zlib:56, xi_sub_residual_zlib:8 | True |
| Unified_Quintic.pdf | 691276 | 597455 | 622300 | 1.111 | 24845 | raw_zlib:169 | True |
| lean4_theorem_proving.pdf | 7449778 | 2641439 | 2755704 | 2.703 | 114265 | raw_zlib:1819 | True |
