import numpy as np

# =========================
# GF(256) implementation
# =========================
PRIMITIVE_POLY = 0x11D
_EXP = None
_LOG = None
_INV = None
_MUL = None

_G_CACHE = {}  # cache generator matrices by (k,r)


def _gf256_init_tables():
    exp = np.zeros(512, dtype=np.uint16)
    log = np.zeros(256, dtype=np.int16)

    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= PRIMITIVE_POLY

    for i in range(255, 512):
        exp[i] = exp[i - 255]

    inv = np.zeros(256, dtype=np.uint8)
    inv[0] = 0
    for a in range(1, 256):
        inv[a] = int(exp[255 - log[a]])

    mul = np.zeros((256, 256), dtype=np.uint8)
    for a in range(256):
        if a == 0:
            continue
        la = log[a]
        # Vectorized population of multiplication table
        # We want mul[a, b] = exp[log[a] + log[b]]
        # But we need to handle b=0 separate generally, but here we run b in 0..255
        # actually simpler loop:
        for b in range(1, 256):
            idx = (la + log[b]) % 255
            mul[a, b] = exp[idx]
        
    mul[0, :] = 0
    mul[:, 0] = 0
    
    return exp.astype(np.uint8), log, inv, mul


def _gf_tables():
    global _EXP, _LOG, _INV, _MUL
    if _MUL is None:
        _EXP, _LOG, _INV, _MUL = _gf256_init_tables()
    return _EXP, _LOG, _INV, _MUL


def _gf_mat_inv(A: np.ndarray) -> np.ndarray:
    """Invert a kxk matrix over GF(256) via Gauss-Jordan elimination."""
    _, _, inv_tbl, mul_tbl = _gf_tables()

    A = A.copy().astype(np.uint8)
    k = A.shape[0]
    I = np.eye(k, dtype=np.uint8)
    aug = np.concatenate([A, I], axis=1)  # k x 2k

    for col in range(k):
        # Find pivot
        pivot_rows = np.where(aug[col:, col] != 0)[0]
        if len(pivot_rows) == 0:
             raise ValueError("Matrix not invertible")
        pivot = pivot_rows[0] + col

        if pivot != col:
            aug[[col, pivot]] = aug[[pivot, col]]

        pv = aug[col, col]
        inv_pv = inv_tbl[pv]
        
        # Normalize pivot row
        if inv_pv != 1:
            # Vectorized row multiplication
            # aug[col] = aug[col] * inv_pv
            aug[col] = mul_tbl[inv_pv, aug[col]]

        # Eliminate other rows
        # Vectorized elimination
        rows_to_elim = np.arange(k)
        rows_to_elim = rows_to_elim[rows_to_elim != col]
        
        # factors = aug[rows_to_elim, col]
        # We need to subtract (XOR) factors * row[col]
        
        # This part is slightly tricky to fully vectorize without temporary huge arrays in Python
        # but iterating rows is fine for small k (k <= 64).
        # Inner loop over columns is the slow part in Python, but here columns are numpy arrays.
        # So "aug[row] ^= mul_tbl[factor][aug[col]]" is already vectorized over columns!
        
        for row in rows_to_elim:
            factor = aug[row, col]
            if factor != 0:
                aug[row] ^= mul_tbl[factor, aug[col]]

    return aug[:, k:]

try:
    from numba import jit
    HAS_NUMBA = True
except ImportError:
    import warnings
    warnings.warn(
        "Numba not available - using pure Python fallback (slower performance). "
        "Install for better speed: pip install numba",
        ImportWarning,
        stacklevel=2
    )
    HAS_NUMBA = False
    def jit(*args, **kwargs):
        def decorator(func): return func
        return decorator

@jit(nopython=True, cache=True)
def _fast_mat_mul(A, B, mul_tbl):
    # Numba optimized version with explicit loops (faster than numpy overhead for small matrices)
    r, n = A.shape
    n2, c = B.shape
    
    # Pre-allocate output
    out = np.zeros((r, c), dtype=np.uint8)
    
    for i in range(r):
        for k in range(n):
            val_a = A[i, k]
            if val_a == 0:
                continue
            
            # Inner loop over columns (shard size)
            # Numba unrolls this very efficiently
            for j in range(c):
                out[i, j] ^= mul_tbl[val_a, B[k, j]]
                
    return out


def _gf_mat_mul(A: np.ndarray, B: np.ndarray) -> np.ndarray:
    """Matrix multiply over GF(256): (r x n) * (n x c) => (r x c)."""
    _, _, _, mul_tbl = _gf_tables()

    A = A.astype(np.uint8)
    B = B.astype(np.uint8)
    r_dim, n_dim = A.shape
    n2, c_dim = B.shape
    if n_dim != n2:
        raise ValueError("Dimension mismatch")

    if HAS_NUMBA:
         # Use Numba-accelerated version
         return _fast_mat_mul(A, B, mul_tbl)

    # Fallback: Optimized NumPy Vectorization
    out = np.zeros((r_dim, c_dim), dtype=np.uint8)
    
    for t in range(n_dim):
        col_vals = A[:, t] # shap (r,)
        b_row = B[t, :]    # shape (c,)
        
        # Find rows where A is not zero
        nz_indices = np.nonzero(col_vals)[0]
        
        for i in nz_indices:
            val_a = col_vals[i]
            out[i] ^= mul_tbl[val_a, b_row]
            
    return out


def _build_generator_matrix(k: int, r: int) -> np.ndarray:
    """
    Build a systematic MDS generator matrix G (m x k) with m=k+r.
    """
    m = k + r
    if m > 255:
        raise ValueError("k+r must be <= 255 for GF(256) MDS code")

    _, _, _, mul_tbl = _gf_tables()

    xs = np.arange(1, m + 1, dtype=np.uint8)  # distinct field elements 1..m
    V = np.zeros((m, k), dtype=np.uint8)
    V[:, 0] = 1
    for j in range(1, k):
        # V[:, j] = mul_tbl[xs][V[:, j - 1]]
        # Vectorized lookup
        V[:, j] = mul_tbl[xs, V[:, j - 1]]

    T = _gf_mat_inv(V[:k, :])
    G = _gf_mat_mul(V, T)

    if not np.all(G[:k] == np.eye(k, dtype=np.uint8)):
        raise ValueError("Failed to build systematic generator matrix")

    return G


def _get_G(k: int, r: int) -> np.ndarray:
    key = (k, r)
    if key not in _G_CACHE:
        _G_CACHE[key] = _build_generator_matrix(k, r)
    return _G_CACHE[key]


def _fec_encode(data_shards: np.ndarray, G: np.ndarray, k: int, r: int) -> np.ndarray:
    """Encode: input (k x L) => output (m x L) with m=k+r (systematic)."""
    _, _, _, mul_tbl = _gf_tables()

    L = data_shards.shape[1]
    m = k + r
    
    # We only need to compute parity rows (indices k..m-1)
    # The first k rows are identical to data_shards (systematic).
    
    # Parity part of G is G[k:, :] which is (r x k)
    # Parity shards = G_parity * data_shards
    
    G_parity = G[k:, :] # r x k
    
    parity_shards = _gf_mat_mul(G_parity, data_shards) # (r x k) * (k x L) => (r x L)
    
    out = np.zeros((m, L), dtype=np.uint8)
    out[:k] = data_shards
    out[k:] = parity_shards

    return out


def _fec_decode(shards: list, present: list, G: np.ndarray, k: int, r: int) -> np.ndarray:
    """
    Decode original data (k x L) from available shards.
    """
    m = k + r
    avail_idx = [i for i in range(m) if present[i]]
    if len(avail_idx) < k:
        raise ValueError("Not enough shards to recover the block")

    use_idx = avail_idx[:k]
    A = G[use_idx, :]  # k x k
    A_inv = _gf_mat_inv(A)

    avail_data = np.stack([shards[i] for i in use_idx], axis=0).astype(np.uint8)  # k x L
    
    # logical data = A_inv * avail_data
    return _gf_mat_mul(A_inv, avail_data)
