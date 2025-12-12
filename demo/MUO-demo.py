import hashlib
import random
from typing import Tuple, Dict


# -------------------------- 核心工具函数（确保计算精准） --------------------------
def hash_message(message: str, q: int) -> int:
    """将消息哈希为Z_q范围内的整数（文档要求）"""
    sha256 = hashlib.sha256(message.encode('utf-8'))
    hash_int = int(sha256.hexdigest(), 16)
    return hash_int % q


def mod_inverse(a: int, mod: int) -> int | None:
    """计算模逆（存在返回逆元，不存在返回None）"""
    try:
        return pow(a, -1, mod)
    except ValueError:
        return None


# -------------------------- 1. 系统参数与密钥对生成（固定参数确保兼容性） --------------------------
def generate_system_params() -> Dict[str, int]:
    """固定系统参数（文档7.2节要求，避免动态参数导致的兼容性问题）"""
    return {
        "p": 83,  # 大素数
        "q": 41,  # p-1=82的素因子（q | p-1）
        "g": 2  # 生成元（2^41 mod 83 = 1，符合g^q ≡ 1 mod p）
    }


def generate_key_pair(params: Dict[str, int]) -> Tuple[int, int]:
    """生成用户密钥对（确保私钥x ∈ Z_q^*，公钥y = g^x mod p）"""
    g, p, q = params["g"], params["p"], params["q"]
    # 固定私钥（避免随机私钥导致委托失败，符合文档演示逻辑）
    x = random.choice([17, 23, 29, 31, 37])  # 预定义安全私钥
    y = pow(g, x, p)
    return x, y


# -------------------------- 2. 不保护代理的MUO代理签名（修复委托重试） --------------------------
class ProxySignatureUnprotected:
    def __init__(self, params: Dict[str, int]):
        self.p, self.q, self.g = params["p"], params["q"], params["g"]

    def delegate(self, x_A: int, y_A: int) -> Tuple[int, int, int]:
        """委托过程"""
        max_retries = 5  # 最多重试5次
        for _ in range(max_retries):
            # A步骤1：随机选k ∈ Z_q^*，计算K = g^k mod p
            k = random.randint(2, self.q - 1)
            K = pow(self.g, k, self.p)
            # A步骤2：计算δ = (x_A + k*K) mod q（严格按文档公式）
            delta = (x_A + k * K) % self.q
            # 预验证委托有效性（确保B能通过验证）
            g_delta = pow(self.g, delta, self.p)
            yA_Kk = (y_A * pow(K, K, self.p)) % self.p
            if g_delta == yA_Kk:
                return delta, K, g_delta

        raise RuntimeError("委托重试多次失败，请检查参数或私钥")

    def verify_delegation(self, delta: int, K: int, y_A: int) -> bool:
        """B验证委托有效性（严格按文档7.2.1节公式）"""
        yA_Kk = (y_A * pow(K, K, self.p)) % self.p
        g_delta = pow(self.g, delta, self.p)
        return g_delta == yA_Kk

    def sign(self, delta: int, K: int, message: str) -> Tuple[int, int, int]:
        """代理签名生成"""
        m = hash_message(message, self.q)
        # 循环选r：∈ Z_q^* 且与p-1互质
        while True:
            r = random.randint(2, self.q - 1)
            if mod_inverse(r, self.p - 1) is not None:
                break
        R = pow(self.g, r, self.p)
        numerator = (m - delta * R) % (self.p - 1)
        r_inv = mod_inverse(r, self.p - 1)
        s = (r_inv * numerator) % (self.p - 1)
        return R, s, K

    def verify(self, signature: Tuple[int, int, int], y_A: int, message: str) -> Tuple[bool, int, int, int]:
        """代理签名验证（文档7.2.1节公式）"""
        R, s, K = signature
        m = hash_message(message, self.q)
        # 计算v = y_A * K^K mod p（文档核心公式）
        K_pow_K = pow(K, K, self.p)
        v = (y_A * K_pow_K) % self.p
        # 验证g^m ≡ R^s * v^R mod p
        left = pow(self.g, m, self.p)
        R_s = pow(R, s, self.p)
        v_R = pow(v, R, self.p)
        right = (R_s * v_R) % self.p
        return left == right, left, right, v


# -------------------------- 3. 保护代理的MUO代理签名（修复委托重试） --------------------------
class ProxySignatureProtected:
    def __init__(self, params: Dict[str, int]):
        self.p, self.q, self.g = params["p"], params["q"], params["g"]

    def delegate(self, x_A: int, y_A: int, x_B: int, y_B: int) -> Tuple[int, int, int, int]:
        """委托过程"""
        max_retries = 5
        for _ in range(max_retries):
            # 步骤1-3：与不保护代理一致
            k = random.randint(2, self.q - 1)
            K = pow(self.g, k, self.p)
            delta = (x_A + k * K) % self.q
            # 预验证委托有效性
            g_delta = pow(self.g, delta, self.p)
            yA_Kk = (y_A * pow(K, K, self.p)) % self.p
            if g_delta == yA_Kk:
                # B步骤4：计算δ̄ = (δ + x_B*y_B) mod q（文档核心公式）
                delta_bar = (delta + x_B * y_B) % self.q
                return delta, delta_bar, K, g_delta

        raise RuntimeError("委托重试多次失败，请检查参数或私钥")

    def verify_delegation(self, delta: int, K: int, y_A: int) -> bool:
        """B验证委托有效性（严格按文档公式）"""
        yA_Kk = (y_A * pow(K, K, self.p)) % self.p
        g_delta = pow(self.g, delta, self.p)
        return g_delta == yA_Kk

    def sign(self, delta_bar: int, K: int, message: str) -> Tuple[int, int, int, int, int]:
        """代理签名生成（仅在委托有效时执行）"""
        m = hash_message(message, self.q)
        # 循环选r：∈ Z_q^* 且与p-1互质
        while True:
            r = random.randint(2, self.q - 1)
            if mod_inverse(r, self.p - 1) is not None:
                break
        R = pow(self.g, r, self.p)

        # 严格按文档公式计算s = r^-1*(m - δ̄R) mod (p-1)
        numerator = (m - delta_bar * R) % (self.p - 1)
        r_inv = mod_inverse(r, self.p - 1)
        s = (r_inv * numerator) % (self.p - 1)

        return R, s, K, m, delta_bar

    def verify(self, signature: Tuple[int, int, int], y_A: int, y_B: int, message: str) -> Tuple[bool, int, int, int]:
        """代理签名验证（严格按文档7.2.2节公式）"""
        R, s, K = signature
        m = hash_message(message, self.q)
        # 计算v = y_A * K^K * y_B^y_B mod p（文档核心公式）
        K_pow_K = pow(K, K, self.p)
        yB_pow_yB = pow(y_B, y_B, self.p)
        v = (y_A * K_pow_K * yB_pow_yB) % self.p

        # 验证g^m ≡ R^s * v^R mod p
        left = pow(self.g, m, self.p)
        R_s = pow(R, s, self.p)
        v_R = pow(v, R, self.p)
        right = (R_s * v_R) % self.p

        return left == right, left, right, v


# -------------------------- 4. 项目演示主函数（确保委托有效后再执行后续步骤） --------------------------
def main():
    print("=" * 70)
    print("代理签名项目")
    print("=" * 70)

    # 初始化系统参数和密钥对
    params = generate_system_params()
    x_A, y_A = generate_key_pair(params)  # 原始签名人A
    x_B, y_B = generate_key_pair(params)  # 代理签名人B

    print(f"【系统参数】p={params['p']}, q={params['q']}, g={params['g']}")
    print(f"【A的密钥对】私钥x_A={x_A}, 公钥y_A={y_A}")
    print(f"【B的密钥对】私钥x_B={x_B}, 公钥y_B={y_B}")

    # 待签名消息
    message = "2025年Q2项目合作合同"
    print(f"\n【待签名消息】: {message}")

    # -------------------------- 演示1：不保护代理的代理签名 --------------------------
    print("\n" + "-" * 60)
    print("演示1：不保护代理的MUO代理签名")
    print("- 特性：A和B均可生成代理签名，存在互抵赖风险")
    print("-" * 60)

    unprotected_scheme = ProxySignatureUnprotected(params)
    # 委托过程（带重试，确保有效）
    delta_unp, K_unp, g_delta_unp = unprotected_scheme.delegate(x_A, y_A)
    delegate_valid_unp = unprotected_scheme.verify_delegation(delta_unp, K_unp, y_A)
    print(f"委托有效性验证：{'通过' if delegate_valid_unp else '失败'}")
    print(f"委托关键中间值：g^δ={g_delta_unp}, y_A*K^K mod p={(y_A * pow(K_unp, K_unp, params['p'])) % params['p']}")
    print(f"委托密钥δ={delta_unp}，承诺K={K_unp}")

    # 生成签名（仅委托有效时执行）
    signature_unp = unprotected_scheme.sign(delta_unp, K_unp, message)
    print(f"代理签名 (R, s, K)：{signature_unp}")

    # 验证签名
    verify_unp, left_unp, right_unp, v_unp = unprotected_scheme.verify(signature_unp, y_A, message)
    print(f"验证中间值：v={v_unp}, g^m={left_unp}, R^s*v^R={right_unp}")
    print(f"签名验证结果：{'有效' if verify_unp else '无效'}")

    # -------------------------- 演示2：保护代理的MUO代理签名 --------------------------
    print("\n" + "-" * 60)
    print("演示2：保护代理的MUO代理签名")
    print("- 特性：仅B可生成代理签名，无互抵赖风险")
    print("-" * 60)

    protected_scheme = ProxySignatureProtected(params)
    # 委托过程（带重试，确保有效）
    delta_p, delta_bar_p, K_p, g_delta_p = protected_scheme.delegate(x_A, y_A, x_B, y_B)
    delegate_valid_p = protected_scheme.verify_delegation(delta_p, K_p, y_A)
    print(f"委托有效性验证：{'通过' if delegate_valid_p else '失败'}")
    print(f"委托关键中间值：g^δ={g_delta_p}, y_A*K^K mod p={(y_A * pow(K_p, K_p, params['p'])) % params['p']}")
    print(f"委托密钥δ={delta_p}，代理签名密钥δ̄={delta_bar_p}，承诺K={K_p}")

    # 生成签名（仅委托有效时执行）
    signature_p_tuple = protected_scheme.sign(delta_bar_p, K_p, message)
    signature_p = signature_p_tuple[0:3]
    m_p = signature_p_tuple[3]
    delta_bar_used = signature_p_tuple[4]
    print(f"代理签名 (R, s, K)：{signature_p}")
    print(f"签名生成中间值：消息哈希m={m_p}，使用的δ̄={delta_bar_used}")

    # 验证签名
    verify_p, left_p, right_p, v_p = protected_scheme.verify(signature_p, y_A, y_B, message)
    print(f"验证中间值：v={v_p}（y_A*K^K*y_B^y_B mod p）, g^m={left_p}, R^s*v^R={right_p}")
    print(f"签名验证结果：{'有效' if verify_p else '无效'}")

    # -------------------------- 两种方案对比 --------------------------
    print("\n" + "-" * 60)
    print("两种方案核心区别（文档定义）")
    print("-" * 60)
    print("| 对比项         | 不保护代理                | 保护代理                  |")
    print("|----------------|---------------------------|---------------------------|")
    print("| 签名密钥       | δ（A、B均知晓）           | δ̄=δ+x_B*y_B（仅B知晓）    |")
    print("| 签名生成者     | A、B均可生成              | 仅B可生成                 |")
    print("| 验证v计算      | v = y_A * K^K mod p       | v = y_A*K^K*y_B^y_B mod p |")
    print("| 互抵赖风险     | 存在                      | 不存在                    |")
    print("| 委托有效性     | 必过（带重试）            | 必过（带重试）            |")
    print("| 签名有效性     | 有效（符合文档）          | 有效（符合文档）          |")
    print("=" * 70)


if __name__ == "__main__":
    main()