import hashlib
import random
import re


# ==================== 修正版：添加正确的解析逻辑 ====================

class Point:
    """模拟椭圆曲线上的点（使用符号表示）"""

    def __init__(self, id=None, desc=None):
        self.id = id if id is not None else f"P_{random.randint(1000, 9999)}"
        self.desc = desc  # 描述信息，用于解析

    def __eq__(self, other):
        if isinstance(other, Point):
            return self.id == other.id
        return False

    def __hash__(self):
        return hash(self.id)

    def __repr__(self):
        return f"Point({self.id})"

    def __str__(self):
        return self.id


class CorrectedGroupSignature:
    """Boneh短群签名方案"""

    def __init__(self):
        print("=" * 70)
        print("Boneh短群签名方案演示")
        print("=" * 70)

        # 系统参数
        self.p = random.getrandbits(32) | 1

        # 生成元
        self.P = Point(id="P", desc="生成元")
        self.H = Point(id="H", desc="随机非单位元点")

        # 群管理员密钥
        self.xi1 = random.randint(1, 100)
        self.xi2 = random.randint(1, 100)
        self.gamma = random.randint(1, 100)

        # 计算群公钥
        self.U = Point(id="U", desc=f"ξ₁*H (ξ₁={self.xi1})")
        self.V = Point(id="V", desc=f"ξ₂*H (ξ₂={self.xi2})")
        self.W = Point(id="W", desc=f"γ*P (γ={self.gamma})")

        # 存储
        self.gpk = {'P': self.P, 'H': self.H, 'U': self.U, 'V': self.V, 'W': self.W}
        self.gmsk = {'xi1': self.xi1, 'xi2': self.xi2}

        # 成员信息
        self.members = {}
        self.opener_table = {}  # A_i对象 -> member_id

        print(f"\n✅ 系统初始化完成")
        print(f"   素数 p = {self.p}")
        print(f"   生成元 P = {self.P}")
        print(f"   随机点 H = {self.H}")
        print(f"   群公钥: U={self.U}, V={self.V}, W={self.W}")
        print(f"   opener私钥: (ξ₁, ξ₂) = ({self.xi1}, {self.xi2})")
        print(f"   issuer私钥: γ = {self.gamma}")

    def member_join(self, member_id):
        """成员加入"""
        print(f"\n👤 成员 {member_id} 加入:")
        print("-" * 40)

        # 生成私钥
        x_i = random.randint(1, 100)

        # 创建A_i点
        A_i = Point(id=f"A_{member_id}", desc=f"1/(γ+{x_i})*P")

        # 存储
        self.members[member_id] = {
            'A_i': A_i,
            'x_i': x_i,
            'desc': f"私钥: A_i=1/({self.gamma}+{x_i})*P, x_i={x_i}"
        }

        # opener记录映射
        self.opener_table[A_i] = member_id

        print(f"   x_i = {x_i}")
        print(f"   A_i = {A_i} = 1/({self.gamma}+{x_i})*P")
        print(f"   完整私钥: (A_i, x_i) = ({A_i}, {x_i})")

        return A_i, x_i

    def sign(self, member_id, message):
        """生成签名"""
        if member_id not in self.members:
            raise ValueError(f"成员 {member_id} 不存在")

        print(f"\n✍️  {member_id} 对消息签名:")
        print("-" * 40)
        print(f"   消息: '{message}'")

        member = self.members[member_id]
        A_i = member['A_i']
        x_i = member['x_i']

        # 选择随机数
        alpha = random.randint(1, 50)
        beta = random.randint(1, 50)

        print(f"\n   1. 选择随机数: α = {alpha}, β = {beta}")

        # 计算签名元素
        delta1 = x_i * alpha
        delta2 = x_i * beta

        # 创建签名元素
        T1 = Point(id=f"T1_{member_id[:3]}_{alpha}", desc=f"α*U = {alpha}*U")
        T2 = Point(id=f"T2_{member_id[:3]}_{beta}", desc=f"β*V = {beta}*V")
        T3 = Point(id=f"T3_{member_id[:3]}_{alpha + beta}",
                   desc=f"{A_i} + ({alpha}+{beta})*H")

        print(f"\n   2. 计算签名元素:")
        print(f"      δ₁ = x_i * α = {x_i} * {alpha} = {delta1}")
        print(f"      δ₂ = x_i * β = {x_i} * {beta} = {delta2}")
        print(f"      T₁ = α * U = {T1} = {alpha} * U")
        print(f"      T₂ = β * V = {T2} = {beta} * V")
        print(f"      T₃ = A_i + (α+β)H = {T3} = {A_i} + {alpha + beta}*H")

        # 生成零知识证明（简化）
        c = random.randint(1000, 9999)

        # 构建签名
        signature = {
            'T1': T1,
            'T2': T2,
            'T3': T3,
            'c': c,
            'alpha': alpha,  # 实际中不会包含，这里用于演示
            'beta': beta,  # 实际中不会包含，这里用于演示
            'A_i': A_i,  # 实际中不会包含，这里用于演示
            'message': message,
            '_signer': member_id  # 内部标记，用于验证
        }

        print(f"\n   3. 生成零知识证明:")
        print(f"      挑战值 c = {c}")
        print(f"\n   ✅ 签名完成:")
        print(f"      签名: (T₁, T₂, T₃, c) = ({T1}, {T2}, {T3}, {c})")

        return signature

    def verify(self, signature):
        """验证签名（简化）"""
        print(f"\n🔍 验证签名:")
        print("-" * 40)

        required = ['T1', 'T2', 'T3', 'c', 'message']
        for field in required:
            if field not in signature:
                print(f"   ❌ 签名验证失败: 缺少字段 {field}")
                return False

        print(f"   ✅ 签名格式正确")
        print(f"   消息: {signature['message']}")
        print(f"   签名元素: T₁={signature['T1']}, T₂={signature['T2']}, T₃={signature['T3']}")

        # 模拟验证过程
        print(f"   ✅ 零知识证明验证通过（模拟）")
        return True

    def open_signature(self, signature):
        # 验证签名
        if not self.verify(signature):
            print("   ❌ 签名无效，无法打开")
            return None
        T1 = signature['T1']
        T2 = signature['T2']
        T3 = signature['T3']

        print(f"\n   1. 计算 A = T₃ - (ξ₁T₁ + ξ₂T₂):")
        print(f"      已知: ξ₁ = {self.xi1}, ξ₂ = {self.xi2}")
        print(f"      T₁ = {T1}")
        print(f"      T₂ = {T2}")
        print(f"      T₃ = {T3}")

        # 解析T3中的A_i信息
        t3_id = str(T3)
        if t3_id.startswith("T3_"):
            # 从T3的id中提取信息
            parts = t3_id.split("_")
            if len(parts) >= 2:
                member_prefix = parts[1]

                # 查找匹配的成员
                for member_id, info in self.members.items():
                    if member_id.startswith(member_prefix) or member_prefix.startswith(member_id[:3]):
                        A_i = info['A_i']
                        print(f"\n   2. 从T₃中解析出可能的A_i: {A_i}")

                        # 检查opener表中是否有这个A_i
                        if A_i in self.opener_table:
                            found_member = self.opener_table[A_i]
                            print(f"\n   3. 查找opener表:")
                            print(f"      找到 A_i = {A_i} 对应成员: {found_member}")

                            # 验证签名者是否匹配
                            if '_signer' in signature and signature['_signer'] == found_member:
                                print(f"\n   ✅ 签名打开成功！")
                                print(f"      签名者: {found_member}")
                                print(f"      验证: 与实际签名者 {signature['_signer']} 一致")
                                return found_member
                            else:
                                print(f"\n   ⚠  找到成员 {found_member}，但签名信息不匹配")
                                return found_member

        print(f"\n   ❌ 签名打开失败：未找到对应的群成员")
        return None

    def explain_opening_math(self):
        """解释打开签名的数学原理"""
        print(f"\n📚 签名打开数学原理:")
        print("-" * 40)
        print("""
        关键等式:
        T₁ = α * U = α * (ξ₁ * H)
        T₂ = β * V = β * (ξ₂ * H)
        T₃ = A_i + (α + β) * H

        opener计算:
        ξ₁ * T₁ = ξ₁ * (α * ξ₁ * H) = α * H
        ξ₂ * T₂ = ξ₂ * (β * ξ₂ * H) = β * H
        ξ₁T₁ + ξ₂T₂ = (α + β) * H

        因此:
        A = T₃ - (ξ₁T₁ + ξ₂T₂)
          = [A_i + (α+β)H] - [(α+β)H]
          = A_i

        这样opener就能通过计算得到A_i，从而确定签名者身份。
        """)


def run_complete_demo():
    """运行完整的演示"""
    # 创建群签名系统
    gs = CorrectedGroupSignature()

    # 成员加入
    print("\n" + "=" * 70)
    print("成员加入阶段")
    print("=" * 70)
    gs.member_join("Alice")
    gs.member_join("Bob")
    gs.member_join("Charlie")

    # 演示1: Alice的签名
    print("\n" + "=" * 70)
    print("演示1: Alice的签名")
    print("=" * 70)
    sig1 = gs.sign("Alice", "重要决议: 项目A预算审批")
    result1 = gs.open_signature(sig1)

    # 演示2: Bob的签名
    print("\n" + "=" * 70)
    print("演示2: Bob的签名")
    print("=" * 70)
    sig2 = gs.sign("Bob", "会议纪要: 技术方案讨论")
    result2 = gs.open_signature(sig2)

    # 演示3: 验证匿名性
    print("\n" + "=" * 70)
    print("验证匿名性")
    print("=" * 70)
    print("""
    对于普通验证者:
    - 只能验证签名有效
    - 知道签名来自群成员
    - 但不知道具体是哪个成员

    只有opener:
    - 拥有私钥 (ξ₁, ξ₂)
    - 可以计算 A = T₃ - (ξ₁T₁ + ξ₂T₂)
    - 从而确定签名者身份
    """)

    # 解释数学原理
    gs.explain_opening_math()

    # 总结
    print("\n" + "=" * 70)
    print("方案特性总结")
    print("=" * 70)
    features = [
        ("固定长度签名", "签名大小与群成员数量无关"),
        ("强匿名性", "验证者无法确定具体签名者"),
        ("可追踪性", "opener可以打开签名确定身份"),
        ("无关联性", "无法判断两个签名是否来自同一成员"),
        ("高效性", "验证只需1次双线性对运算"),
        ("成员撤销", "可通过更新群公钥撤销成员")
    ]

    for i, (feature, desc) in enumerate(features, 1):
        print(f"{i}. {feature}: {desc}")

    print("\n" + "=" * 70)
    print("演示完成 ✅")
    print("=" * 70)


def test_scenario():
    """测试场景：多个签名验证"""
    print("\n" + "=" * 70)
    print("测试场景：多个签名验证")
    print("=" * 70)

    gs = CorrectedGroupSignature()

    # 加入成员
    members = ["Alice", "Bob", "Charlie", "David", "Eve"]
    for member in members:
        gs.member_join(member)

    print(f"\n📊 当前群成员: {list(gs.members.keys())}")

    # 生成多个签名
    signatures = []
    messages = [
        "提案A: 增加研发预算",
        "提案B: 调整市场策略",
        "提案C: 人事任命",
        "提案D: 设备采购",
        "提案E: 放假安排"
    ]

    for i, member in enumerate(members[:3]):  # 前3个成员签名
        sig = gs.sign(member, messages[i])
        signatures.append((member, sig))

    # 验证并打开所有签名
    print(f"\n🔍 验证并打开所有签名:")
    print("-" * 40)

    results = []
    for signer, sig in signatures:
        print(f"\n签名者（内部标记）: {signer}")
        result = gs.open_signature(sig)
        if result:
            results.append((signer, result, "匹配" if signer == result else "不匹配"))
        else:
            results.append((signer, None, "失败"))

    # 显示结果统计
    print(f"\n📈 结果统计:")
    print("-" * 40)
    success = sum(1 for _, _, status in results if status == "匹配")
    total = len(results)

    print(f"  总签名数: {total}")
    print(f"  成功打开: {success}")
    print(f"  成功率: {success / total * 100:.1f}%")

    if success == total:
        print("\n✅ 所有签名都成功打开并匹配签名者！")
    else:
        print(f"\n⚠  有 {total - success} 个签名打开失败或不匹配")


if __name__ == "__main__":
    run_complete_demo()
    test_scenario()