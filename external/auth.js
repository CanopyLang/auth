// Canopy Auth FFI -- Base64url decoding, PKCE crypto, and token storage
//
// Imported in Auth modules via:
//   foreign import javascript "external/auth.js" as AuthFFI


// BASE64URL DECODING

/**
 * Decode a base64url-encoded string to a UTF-8 string.
 *
 * @canopy-type String -> Result String String
 * @name base64UrlDecode
 */
var base64UrlDecode = function(input) {
    try {
        var base64 = input.replace(/-/g, '+').replace(/_/g, '/');
        var pad = base64.length % 4;
        if (pad === 2) {
            base64 += '==';
        } else if (pad === 3) {
            base64 += '=';
        } else if (pad === 1) {
            return _Result_Err('Invalid base64url length');
        }
        var decoded = atob(base64);
        var bytes = new Uint8Array(decoded.length);
        for (var i = 0; i < decoded.length; i++) {
            bytes[i] = decoded.charCodeAt(i);
        }
        var text = new TextDecoder('utf-8').decode(bytes);
        return _Result_Ok(text);
    } catch (e) {
        return _Result_Err('Base64url decode failed: ' + e.message);
    }
};


// PKCE CHALLENGE GENERATION

/**
 * Generate a cryptographically random code verifier string (43 chars).
 *
 * @canopy-type () -> Task String String
 * @name generateCodeVerifier
 */
var generateCodeVerifier = function(_v0) {
    return _Scheduler_binding(function(callback) {
        try {
            var unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            var array = new Uint8Array(43);
            crypto.getRandomValues(array);
            var verifier = '';
            for (var i = 0; i < array.length; i++) {
                verifier += unreserved[array[i] % unreserved.length];
            }
            callback(_Scheduler_succeed(verifier));
        } catch (e) {
            callback(_Scheduler_fail('Failed to generate code verifier: ' + e.message));
        }
    });
};


/**
 * Compute the SHA-256 code challenge from a code verifier (base64url-encoded).
 *
 * @canopy-type String -> Task String String
 * @name computeCodeChallenge
 */
var computeCodeChallenge = function(verifier) {
    return _Scheduler_binding(function(callback) {
        try {
            var encoder = new TextEncoder();
            var data = encoder.encode(verifier);
            crypto.subtle.digest('SHA-256', data).then(function(hashBuffer) {
                var hashArray = new Uint8Array(hashBuffer);
                var base64 = '';
                var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
                for (var i = 0; i < hashArray.length; i += 3) {
                    var a = hashArray[i];
                    var b = i + 1 < hashArray.length ? hashArray[i + 1] : 0;
                    var c = i + 2 < hashArray.length ? hashArray[i + 2] : 0;
                    base64 += chars[a >> 2];
                    base64 += chars[((a & 3) << 4) | (b >> 4)];
                    base64 += (i + 1 < hashArray.length) ? chars[((b & 15) << 2) | (c >> 6)] : '';
                    base64 += (i + 2 < hashArray.length) ? chars[c & 63] : '';
                }
                var base64url = base64.replace(/\+/g, '-').replace(/\//g, '_');
                callback(_Scheduler_succeed(base64url));
            }).catch(function(e) {
                callback(_Scheduler_fail('SHA-256 failed: ' + e.message));
            });
        } catch (e) {
            callback(_Scheduler_fail('Code challenge failed: ' + e.message));
        }
    });
};


/**
 * Generate a cryptographically random state string (32-char hex).
 *
 * @canopy-type () -> Task Never String
 * @name generateRandomState
 */
var generateRandomState = function(_v0) {
    return _Scheduler_binding(function(callback) {
        var array = new Uint8Array(16);
        crypto.getRandomValues(array);
        var hex = '';
        for (var i = 0; i < array.length; i++) {
            hex += ('0' + array[i].toString(16)).slice(-2);
        }
        callback(_Scheduler_succeed(hex));
    });
};


// TOKEN STORAGE
//
// Security model:
//   - Access tokens: ALWAYS stored in memory only (never localStorage/sessionStorage).
//     XSS cannot read them; they are lost on page unload (intended).
//   - Refresh tokens: May use localStorage or sessionStorage per the caller's strategy.
//     These are longer-lived and may survive page reloads as designed.
//
// Strategy tags: 0=localStorage, 1=sessionStorage, 2=memoryOnly

var _Auth_accessTokenKey = '__canopy_auth_access';
var _Auth_refreshTokenKey = '__canopy_auth_refresh';
var _Auth_accessMemory = null;  // in-memory access token storage

// Clear in-memory access token when the tab closes so it does not persist
// across sessions even accidentally (e.g., via bfcache restoration).
if (typeof window !== 'undefined') {
    window.addEventListener('beforeunload', function() {
        _Auth_accessMemory = null;
    });
}

function _Auth_getStorageObj(tag) {
    if (tag === 'LocalStorage' || tag === 0) {
        return typeof localStorage !== 'undefined' ? localStorage : null;
    }
    if (tag === 'SessionStorage' || tag === 1) {
        return typeof sessionStorage !== 'undefined' ? sessionStorage : null;
    }
    return null;
}


/**
 * Save an access token JSON string. Always stored in memory, never
 * in localStorage or sessionStorage, to prevent XSS exfiltration.
 *
 * @canopy-type String -> Task Never ()
 * @name saveAccessToken
 */
var saveAccessToken = function(jsonStr) {
    return _Scheduler_binding(function(callback) {
        _Auth_accessMemory = jsonStr;
        callback(_Scheduler_succeed(_Utils_Tuple0));
    });
};


/**
 * Load the access token JSON string from memory.
 *
 * @canopy-type () -> Task Never (Maybe String)
 * @name loadAccessToken
 */
var loadAccessToken = function(_v0) {
    return _Scheduler_binding(function(callback) {
        if (_Auth_accessMemory === null || _Auth_accessMemory === undefined) {
            callback(_Scheduler_succeed(_Maybe_Nothing));
        } else {
            callback(_Scheduler_succeed(_Maybe_Just(_Auth_accessMemory)));
        }
    });
};


/**
 * Clear the in-memory access token.
 *
 * @canopy-type () -> Task Never ()
 * @name clearAccessToken
 */
var clearAccessToken = function(_v0) {
    return _Scheduler_binding(function(callback) {
        _Auth_accessMemory = null;
        callback(_Scheduler_succeed(_Utils_Tuple0));
    });
};


/**
 * Save a refresh token JSON string to the configured persistent storage.
 * Tag: 0=localStorage, 1=sessionStorage, 2=memoryOnly.
 * Returns Err "QuotaExceeded" if storage quota is exceeded.
 *
 * @canopy-type Int -> String -> Task String ()
 * @name saveRefreshToken
 */
var saveRefreshToken = F2(function(strategyTag, jsonStr) {
    return _Scheduler_binding(function(callback) {
        var storage = _Auth_getStorageObj(strategyTag);
        if (storage) {
            try {
                storage.setItem(_Auth_refreshTokenKey, jsonStr);
                callback(_Scheduler_succeed(_Utils_Tuple0));
            } catch (e) {
                if (e && e.name === 'QuotaExceededError') {
                    callback(_Scheduler_fail('QuotaExceeded'));
                } else {
                    callback(_Scheduler_fail(e ? e.message : 'StorageError'));
                }
            }
        } else {
            // MemoryOnly strategy for refresh token: use memory store
            _Auth_accessMemory = jsonStr;
            callback(_Scheduler_succeed(_Utils_Tuple0));
        }
    });
});


/**
 * Load a refresh token JSON string from the configured persistent storage.
 *
 * @canopy-type Int -> Task Never (Maybe String)
 * @name loadRefreshToken
 */
var loadRefreshToken = function(strategyTag) {
    return _Scheduler_binding(function(callback) {
        var storage = _Auth_getStorageObj(strategyTag);
        var json = null;
        if (storage) {
            try { json = storage.getItem(_Auth_refreshTokenKey); }
            catch (e) { /* storage unavailable */ }
        }
        if (json === null || json === undefined) {
            callback(_Scheduler_succeed(_Maybe_Nothing));
        } else {
            callback(_Scheduler_succeed(_Maybe_Just(json)));
        }
    });
};


/**
 * Clear the refresh token from the configured persistent storage.
 *
 * @canopy-type Int -> Task Never ()
 * @name clearRefreshToken
 */
var clearRefreshToken = function(strategyTag) {
    return _Scheduler_binding(function(callback) {
        var storage = _Auth_getStorageObj(strategyTag);
        if (storage) {
            try { storage.removeItem(_Auth_refreshTokenKey); }
            catch (e) { /* storage unavailable */ }
        }
        callback(_Scheduler_succeed(_Utils_Tuple0));
    });
};


// Legacy API: kept for backwards compatibility with callers that use the
// old unified saveTokenString / loadTokenString / clearTokenString API.
// These now store the payload in memory only regardless of strategy tag,
// matching the secure default. Callers should migrate to the split API.

var _Auth_legacyMemory = null;

/**
 * @canopy-type Int -> String -> Task Never ()
 * @name saveTokenString
 * @deprecated Use saveAccessToken and saveRefreshToken instead.
 */
var saveTokenString = F2(function(strategyTag, jsonStr) {
    return _Scheduler_binding(function(callback) {
        _Auth_legacyMemory = jsonStr;
        callback(_Scheduler_succeed(_Utils_Tuple0));
    });
});


/**
 * @canopy-type Int -> Task Never (Maybe String)
 * @name loadTokenString
 * @deprecated Use loadAccessToken and loadRefreshToken instead.
 */
var loadTokenString = function(strategyTag) {
    return _Scheduler_binding(function(callback) {
        if (_Auth_legacyMemory === null || _Auth_legacyMemory === undefined) {
            callback(_Scheduler_succeed(_Maybe_Nothing));
        } else {
            callback(_Scheduler_succeed(_Maybe_Just(_Auth_legacyMemory)));
        }
    });
};


/**
 * @canopy-type Int -> Task Never ()
 * @name clearTokenString
 * @deprecated Use clearAccessToken and clearRefreshToken instead.
 */
var clearTokenString = function(strategyTag) {
    return _Scheduler_binding(function(callback) {
        _Auth_legacyMemory = null;
        callback(_Scheduler_succeed(_Utils_Tuple0));
    });
};
