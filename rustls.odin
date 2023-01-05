/*
 * Copyright 2022 XXIV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package rustls

import c "core:c"

when ODIN_OS == .Linux {
    when #config(shared, true) {
        foreign import lib "librustls_ffi.so" 
    } else {
        foreign import lib "librustls_ffi.a"
    }
} else when ODIN_OS == .Windows  {
    when #config(shared, true) {
        foreign import lib "librustls_ffi.dll" 
    } else {
        foreign import lib "librustls_ffi.lib"
    }
} else when ODIN_OS == .Darwin {
    when #config(shared, true) {
        foreign import lib "librustls_ffi.dylib" 
    } else {
        foreign import lib "librustls_ffi.a"
    }
} else {
	foreign import lib "system:rustls_ffi"
}

rustls_verify_server_cert_user_data :: rawptr
rustls_verify_server_cert_callback :: #type proc(userdata : rustls_verify_server_cert_user_data,
						 params : ^rustls_verify_server_cert_params) -> u32
rustls_log_level :: c.size_t
rustls_log_callback :: #type proc(userdata : rawptr,
				  params : ^rustls_log_params)
rustls_io_result :: c.int
rustls_read_callback :: #type proc(userdata : rawptr,
				   buf : ^u8,
				   n : c.size_t,
				   out_n : ^c.size_t) -> c.int
rustls_write_callback :: #type proc(userdata : rawptr,
				    buf : ^u8,
				    n : c.size_t,
				    out_n : ^c.size_t) -> c.int
rustls_write_vectored_callback :: #type proc(userdata : rawptr,
					     iov : ^rustls_iovec,
					     count : c.size_t,
					     out_n : ^c.size_t) -> c.int
rustls_client_hello_userdata :: rawptr
rustls_client_hello_callback :: #type proc(userdata : rustls_client_hello_userdata,
					   hello : ^rustls_client_hello) -> ^rustls_certified_key
rustls_session_store_userdata :: rawptr
rustls_session_store_get_callback :: #type proc(userdata : rustls_session_store_userdata,
						key : ^rustls_slice_bytes,
						remove_after : c.int,
						buf : ^u8,
						count : c.size_t,
						out_n : ^c.size_t) -> u32
rustls_session_store_put_callback :: #type proc(userdata : rustls_session_store_userdata,
						key : ^rustls_slice_bytes,
						val : ^rustls_slice_bytes) -> u32

rustls_result :: enum {
    OK = 7000,
    IO = 7001,
    NULL_PARAMETER = 7002,
    INVALID_DNS_NAME_ERROR = 7003,
    PANIC = 7004,
    CERTIFICATE_PARSE_ERROR = 7005,
    PRIVATE_KEY_PARSE_ERROR = 7006,
    INSUFFICIENT_SIZE = 7007,
    NOT_FOUND = 7008,
    INVALID_PARAMETER = 7009,
    UNEXPECTED_EOF = 7010,
    PLAINTEXT_EMPTY = 7011,
    CORRUPT_MESSAGE = 7100,
    NO_CERTIFICATES_PRESENTED = 7101,
    DECRYPT_ERROR = 7102,
    FAILED_TO_GET_CURRENT_TIME = 7103,
    FAILED_TO_GET_RANDOM_BYTES = 7113,
    HANDSHAKE_NOT_COMPLETE = 7104,
    PEER_SENT_OVERSIZED_RECORD = 7105,
    NO_APPLICATION_PROTOCOL = 7106,
    BAD_MAX_FRAGMENT_SIZE = 7114,
    UNSUPPORTED_NAME_TYPE = 7115,
    ENCRYPT_ERROR = 7116,
    CERT_INVALID_ENCODING = 7117,
    CERT_INVALID_SIGNATURE_TYPE = 7118,
    CERT_INVALID_SIGNATURE = 7119,
    CERT_INVALID_DATA = 7120,
    PEER_INCOMPATIBLE_ERROR = 7107,
    PEER_MISBEHAVED_ERROR = 7108,
    INAPPROPRIATE_MESSAGE = 7109,
    INAPPROPRIATE_HANDSHAKE_MESSAGE = 7110,
    CORRUPT_MESSAGE_PAYLOAD = 7111,
    GENERAL = 7112,
    ALERT_CLOSE_NOTIFY = 7200,
    ALERT_UNEXPECTED_MESSAGE = 7201,
    ALERT_BAD_RECORD_MAC = 7202,
    ALERT_DECRYPTION_FAILED = 7203,
    ALERT_RECORD_OVERFLOW = 7204,
    ALERT_DECOMPRESSION_FAILURE = 7205,
    ALERT_HANDSHAKE_FAILURE = 7206,
    ALERT_NO_CERTIFICATE = 7207,
    ALERT_BAD_CERTIFICATE = 7208,
    ALERT_UNSUPPORTED_CERTIFICATE = 7209,
    ALERT_CERTIFICATE_REVOKED = 7210,
    ALERT_CERTIFICATE_EXPIRED = 7211,
    ALERT_CERTIFICATE_UNKNOWN = 7212,
    ALERT_ILLEGAL_PARAMETER = 7213,
    ALERT_UNKNOWN_CA = 7214,
    ALERT_ACCESS_DENIED = 7215,
    ALERT_DECODE_ERROR = 7216,
    ALERT_DECRYPT_ERROR = 7217,
    ALERT_EXPORT_RESTRICTION = 7218,
    ALERT_PROTOCOL_VERSION = 7219,
    ALERT_INSUFFICIENT_SECURITY = 7220,
    ALERT_INTERNAL_ERROR = 7221,
    ALERT_INAPPROPRIATE_FALLBACK = 7222,
    ALERT_USER_CANCELED = 7223,
    ALERT_NO_RENEGOTIATION = 7224,
    ALERT_MISSING_EXTENSION = 7225,
    ALERT_UNSUPPORTED_EXTENSION = 7226,
    ALERT_CERTIFICATE_UNOBTAINABLE = 7227,
    ALERT_UNRECOGNISED_NAME = 7228,
    ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 7229,
    ALERT_BAD_CERTIFICATE_HASH_VALUE = 7230,
    ALERT_UNKNOWN_PSK_IDENTITY = 7231,
    ALERT_CERTIFICATE_REQUIRED = 7232,
    ALERT_NO_APPLICATION_PROTOCOL = 7233,
    ALERT_UNKNOWN = 7234,
    CERT_SCT_MALFORMED = 7319,
    CERT_SCT_INVALID_SIGNATURE = 7320,
    CERT_SCT_TIMESTAMP_IN_FUTURE = 7321,
    CERT_SCT_UNSUPPORTED_VERSION = 7322,
    CERT_SCT_UNKNOWN_LOG = 7323
}

rustls_tls_version :: enum {
    VERSION_SSLV2 = 512,
    VERSION_SSLV3 = 768,
    VERSION_TLSV1_0 = 769,
    VERSION_TLSV1_1 = 770,
    VERSION_TLSV1_2 = 771,
    VERSION_TLSV1_3 = 772
}

rustls_certificate :: struct {}

rustls_certified_key :: struct {}

rustls_client_cert_verifier :: struct {}

rustls_client_cert_verifier_optional :: struct {}

rustls_client_config :: struct {}

rustls_client_config_builder :: struct {}

rustls_connection :: struct {}

rustls_iovec :: struct {}

rustls_root_cert_store :: struct {}

rustls_server_config :: struct {}

rustls_server_config_builder :: struct {}

rustls_slice_slice_bytes :: struct {}

rustls_slice_str :: struct {}

rustls_supported_ciphersuite :: struct {}

rustls_str :: struct {
    data : cstring,
    len : c.size_t,
}

rustls_slice_bytes :: struct {
    data : ^u8,
    len : c.size_t,
}

rustls_verify_server_cert_params :: struct {
    end_entity_cert_der : rustls_slice_bytes,
    intermediate_certs_der : ^rustls_slice_slice_bytes,
    dns_name : rustls_str,
    ocsp_response : rustls_slice_bytes,
}

rustls_log_params :: struct {
    level : c.size_t,
    message : rustls_str,
}

rustls_slice_u16 :: struct {
    data : ^u16,
    len : c.size_t,
}

rustls_client_hello :: struct {
    sni_name : rustls_str,
    signature_schemes : rustls_slice_u16,
    alpn : ^rustls_slice_slice_bytes,
}

foreign lib {

    
    RUSTLS_ALL_CIPHER_SUITES : ^rustls_supported_ciphersuite

    
    RUSTLS_ALL_CIPHER_SUITES_LEN : c.size_t

    
    RUSTLS_DEFAULT_CIPHER_SUITES : ^rustls_supported_ciphersuite

    
    RUSTLS_DEFAULT_CIPHER_SUITES_LEN : c.size_t

    
    RUSTLS_ALL_VERSIONS : u16

    
    RUSTLS_ALL_VERSIONS_LEN : c.size_t

    
    RUSTLS_DEFAULT_VERSIONS : u16

    
    RUSTLS_DEFAULT_VERSIONS_LEN : c.size_t

    
    rustls_version :: proc() -> rustls_str ---

    
    rustls_certificate_get_der :: proc(cert : ^rustls_certificate,
				       out_der_data : ^^u8,
				       out_der_len : ^c.size_t) -> u32 ---

    
    rustls_supported_ciphersuite_get_suite :: proc(supported_ciphersuite : ^rustls_supported_ciphersuite) -> u16 ---

    
    rustls_supported_ciphersuite_get_name :: proc(supported_ciphersuite : ^rustls_supported_ciphersuite) -> rustls_str ---

    
    rustls_all_ciphersuites_len :: proc() -> c.size_t ---

    
    rustls_all_ciphersuites_get_entry :: proc(i : c.size_t) -> ^rustls_supported_ciphersuite ---

    
    rustls_default_ciphersuites_len :: proc() -> c.size_t ---

    
    rustls_default_ciphersuites_get_entry :: proc(i : c.size_t) -> ^rustls_supported_ciphersuite ---

    
    rustls_certified_key_build :: proc(cert_chain : ^u8,
				       cert_chain_len : c.size_t,
				       private_key : ^u8,
				       private_key_len : c.size_t,
				       certified_key_out : ^^rustls_certified_key) -> u32 ---

    
    rustls_certified_key_get_certificate :: proc(certified_key : ^rustls_certified_key,
						 i : c.size_t) -> ^rustls_certificate ---

    
    rustls_certified_key_clone_with_ocsp :: proc(certified_key : ^rustls_certified_key,
						 ocsp_response : ^rustls_slice_bytes,
						 cloned_key_out : ^^rustls_certified_key) -> u32 ---

    
    rustls_certified_key_free :: proc(key : ^rustls_certified_key) ---

    
    rustls_root_cert_store_new :: proc() -> ^rustls_root_cert_store ---

    
    rustls_root_cert_store_add_pem :: proc(store : ^rustls_root_cert_store,
					   pem : ^u8,
					   pem_len : c.size_t,
					   strict : bool) -> u32 ---

    
    rustls_root_cert_store_free :: proc(store : ^rustls_root_cert_store) ---

    
    rustls_client_cert_verifier_new :: proc(store : ^rustls_root_cert_store) -> ^rustls_client_cert_verifier ---

    
    rustls_client_cert_verifier_free :: proc(verifier : ^rustls_client_cert_verifier) ---

    
    rustls_client_cert_verifier_optional_new :: proc(store : ^rustls_root_cert_store) -> ^rustls_client_cert_verifier_optional ---

    
    rustls_client_cert_verifier_optional_free :: proc(verifier : ^rustls_client_cert_verifier_optional) ---

    
    rustls_client_config_builder_new :: proc() -> ^rustls_client_config_builder ---

    
    rustls_client_config_builder_new_custom :: proc(cipher_suites : ^^rustls_supported_ciphersuite,
						    cipher_suites_len : c.size_t,
						    tls_versions : ^u16,
						    tls_versions_len : c.size_t,
						    builder_out : ^^rustls_client_config_builder) -> u32 ---

    
    rustls_client_config_builder_dangerous_set_certificate_verifier :: proc(config_builder : ^rustls_client_config_builder,
									    callback : rustls_verify_server_cert_callback) -> u32 ---

    
    rustls_client_config_builder_use_roots :: proc(config_builder : ^rustls_client_config_builder,
						   roots : ^rustls_root_cert_store) -> u32 ---

    
    rustls_client_config_builder_load_roots_from_file :: proc(config_builder : ^rustls_client_config_builder,
							      filename : cstring) -> u32 ---

    
    rustls_client_config_builder_set_alpn_protocols :: proc(builder : ^rustls_client_config_builder,
							    protocols : ^rustls_slice_bytes,
							    len : c.size_t) -> u32 ---

    
    rustls_client_config_builder_set_enable_sni :: proc(config : ^rustls_client_config_builder,
							enable : bool) ---

    
    rustls_client_config_builder_set_certified_key :: proc(builder : ^rustls_client_config_builder,
							   certified_keys : ^^rustls_certified_key,
							   certified_keys_len : c.size_t) -> u32 ---

    
    rustls_client_config_builder_build :: proc(builder : ^rustls_client_config_builder) -> ^rustls_client_config ---

    
    rustls_client_config_builder_free :: proc(config : ^rustls_client_config_builder) ---

    
    rustls_client_config_free :: proc(config : ^rustls_client_config) ---

    
    rustls_client_connection_new :: proc(config : ^rustls_client_config,
					 hostname : cstring,
					 conn_out : ^^rustls_connection) -> u32 ---

    
    rustls_connection_set_userdata :: proc(conn : ^rustls_connection,
					   userdata : rawptr) ---

    
    rustls_connection_set_log_callback :: proc(conn : ^rustls_connection,
					       cb : rustls_log_callback) ---

    
    rustls_connection_read_tls :: proc(conn : ^rustls_connection,
				       callback : rustls_read_callback,
				       userdata : rawptr,
				       out_n : ^c.size_t) -> c.int ---

    
    rustls_connection_write_tls :: proc(conn : ^rustls_connection,
					callback : rustls_write_callback,
					userdata : rawptr,
					out_n : ^c.size_t) -> c.int ---

    
    rustls_connection_write_tls_vectored :: proc(conn : ^rustls_connection,
						 callback : rustls_write_vectored_callback,
						 userdata : rawptr,
						 out_n : ^c.size_t) -> c.int ---

    
    rustls_connection_process_new_packets :: proc(conn : ^rustls_connection) -> u32 ---

    
    rustls_connection_wants_read :: proc(conn : ^rustls_connection) -> bool ---

    
    rustls_connection_wants_write :: proc(conn : ^rustls_connection) -> bool ---

    
    rustls_connection_is_handshaking :: proc(conn : ^rustls_connection) -> bool ---

    
    rustls_connection_set_buffer_limit :: proc(conn : ^rustls_connection,
					       n : c.size_t) ---

    
    rustls_connection_send_close_notify :: proc(conn : ^rustls_connection) ---

    
    rustls_connection_get_peer_certificate :: proc(conn : ^rustls_connection,
						   i : c.size_t) -> ^rustls_certificate ---

    
    rustls_connection_get_alpn_protocol :: proc(conn : ^rustls_connection,
						protocol_out : ^^u8,
						protocol_out_len : ^c.size_t) ---

    
    rustls_connection_get_protocol_version :: proc(conn : ^rustls_connection) -> u16 ---

    
    rustls_connection_get_negotiated_ciphersuite :: proc(conn : ^rustls_connection) -> ^rustls_supported_ciphersuite ---

    
    rustls_connection_write :: proc(conn : ^rustls_connection,
				    buf : ^u8,
				    count : c.size_t,
				    out_n : ^c.size_t) -> u32 ---

    
    rustls_connection_read :: proc(conn : ^rustls_connection,
				   buf : ^u8,
				   count : c.size_t,
				   out_n : ^c.size_t) -> u32 ---

    
    rustls_connection_free :: proc(conn : ^rustls_connection) ---

    
    rustls_error :: proc(result : c.uint,
			 buf : cstring,
			 len : c.size_t,
			 out_n : ^c.size_t) ---

    
    rustls_result_is_cert_error :: proc(result : c.uint) -> bool ---

    
    rustls_log_level_str :: proc(level : c.size_t) -> rustls_str ---

    
    rustls_slice_slice_bytes_len :: proc(input : ^rustls_slice_slice_bytes) -> c.size_t ---

    
    rustls_slice_slice_bytes_get :: proc(input : ^rustls_slice_slice_bytes,
					 n : c.size_t) -> rustls_slice_bytes ---

    
    rustls_slice_str_len :: proc(input : ^rustls_slice_str) -> c.size_t ---

    
    rustls_slice_str_get :: proc(input : ^rustls_slice_str,
				 n : c.size_t) -> rustls_str ---

    
    rustls_server_config_builder_new :: proc() -> ^rustls_server_config_builder ---

    
    rustls_server_config_builder_new_custom :: proc(cipher_suites : ^^rustls_supported_ciphersuite,
						    cipher_suites_len : c.size_t,
						    tls_versions : ^u16,
						    tls_versions_len : c.size_t,
						    builder_out : ^^rustls_server_config_builder) -> u32 ---

    
    rustls_server_config_builder_set_client_verifier :: proc(builder : ^rustls_server_config_builder,
							     verifier : ^rustls_client_cert_verifier) ---

    
    rustls_server_config_builder_set_client_verifier_optional :: proc(builder : ^rustls_server_config_builder,
								      verifier : ^rustls_client_cert_verifier_optional) ---

    
    rustls_server_config_builder_free :: proc(config : ^rustls_server_config_builder) ---

    
    rustls_server_config_builder_set_ignore_client_order :: proc(builder : ^rustls_server_config_builder,
								 ignore : bool) -> u32 ---

    
    rustls_server_config_builder_set_alpn_protocols :: proc(builder : ^rustls_server_config_builder,
							    protocols : ^rustls_slice_bytes,
							    len : c.size_t) -> u32 ---

    
    rustls_server_config_builder_set_certified_keys :: proc(builder : ^rustls_server_config_builder,
							    certified_keys : ^^rustls_certified_key,
							    certified_keys_len : c.size_t) -> u32 ---

    
    rustls_server_config_builder_build :: proc(builder : ^rustls_server_config_builder) -> ^rustls_server_config ---

    
    rustls_server_config_free :: proc(config : ^rustls_server_config) ---

    
    rustls_server_connection_new :: proc(config : ^rustls_server_config,
					 conn_out : ^^rustls_connection) -> u32 ---

    
    rustls_server_connection_get_sni_hostname :: proc(conn : ^rustls_connection,
						      buf : ^u8,
						      count : c.size_t,
						      out_n : ^c.size_t) -> u32 ---

    
    rustls_server_config_builder_set_hello_callback :: proc(builder : ^rustls_server_config_builder,
							    callback : rustls_client_hello_callback) -> u32 ---

    
    rustls_client_hello_select_certified_key :: proc(hello : ^rustls_client_hello,
						     certified_keys : ^^rustls_certified_key,
						     certified_keys_len : c.size_t,
						     out_key : ^^rustls_certified_key) -> u32 ---

    
    rustls_server_config_builder_set_persistence :: proc(builder : ^rustls_server_config_builder,
							 get_cb : rustls_session_store_get_callback,
							 put_cb : rustls_session_store_put_callback) -> u32 ---

}
