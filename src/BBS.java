import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class BBS {
    public static void main(String[] args) {
        //1.System Initialization
        long startInitialize = System.nanoTime();
        //双线性配对初始化,f类椭圆曲线生成非对称的双线性群，配对运算时间长，安全性更强
        Pairing bp = PairingFactory.getPairing("f.properties");
        Field G1 = bp.getG1(); // 群G1
        Field G2 = bp.getG2();// 群G2
        Field Zr = bp.getZr();// 整数环Zr
        //int n;
        long endInitialize = System.nanoTime();
        long timeInitialize = endInitialize - startInitialize; //unit is nanosecond
        System.out.println("System Initialization time: "+timeInitialize/(1e6)+"ms");


        //2.Key Generation
        long startGenKey = System.nanoTime();

        Element g1 = G1.newRandomElement().getImmutable();// 生成群公钥
        Element g2 = G2.newRandomElement().getImmutable();
        Element h = G1.newRandomElement().getImmutable();
        Element xi_1 = Zr.newRandomElement().getImmutable();
        Element xi_2 = Zr.newRandomElement().getImmutable();
        Element u=h.powZn(xi_1.invert()).getImmutable();
        Element v=h.powZn(xi_2.invert()).getImmutable();
        Element gamma = Zr.newRandomElement().getImmutable();
        Element omega = g2.powZn(gamma).getImmutable();
           /*System.out.println(h);
        System.out.println(u.powZn(xi_1));
        System.out.println(v.powZn(xi_2));
        System.out.println((u.powZn(xi_1)).isEqual(v.powZn(xi_2)));*/
        // 公钥输出部分：
        System.out.println("group public key:");
        System.out.println("g1: " + g1);
        System.out.println("g2: " + g2);
        System.out.println("h: " + h);
        System.out.println("u: " + u);
        System.out.println("v: " + v);
        System.out.println("omega: " + omega);
        // 管理员私钥输出
        System.out.println("\nmanger private key:");
        System.out.println("xi_1: " + xi_1);
        System.out.println("xi_2: " + xi_2);

        //member private key
        Element x = Zr.newRandomElement().getImmutable();// 随机数x
        Element gammaAddx = gamma.add(x).getImmutable();
//        System.out.println(gammaAddx);
//        System.out.println(x.add(gamma));
        //member private key
        Element A = g1.powZn(gammaAddx.invert()).getImmutable();// 生成成员私钥 A = g₁^{1/(γ+x)}
        //check if private key forged by non-group member can succeed to pass verification
        //Element A = G1.newRandomElement().getImmutable(); //verification failed
//        System.out.println(x);
//        System.out.println(A);
        // 成员私钥输出：
        System.out.println("\ngroup member private key:");
        System.out.println("A: " + A);
        System.out.println("x: " + x);
        long endGenKey = System.nanoTime();
        long timeGenKey = endGenKey - startGenKey; //unit is nanosecond
        System.out.println("Key Generation time: "+timeGenKey/(1e6)+"ms");


        //3.Signing
        long startSign = System.nanoTime();
        Element alpha = Zr.newRandomElement().getImmutable();
        Element beta = Zr.newRandomElement().getImmutable();
        Element T1 = u.powZn(alpha).getImmutable();   // T₁ = u^α
        Element T2 = v.powZn(beta).getImmutable();  // T₂ = v^β
        Element alphaAddBeta = alpha.add(beta);
        Element hPowAlphaAddBeta = h.powZn(alphaAddBeta);
        Element T3 = A.mul(hPowAlphaAddBeta).getImmutable();// 生成签名T3 T₃ = A·h^{α+β}

        Element r_alpha = Zr.newRandomElement().getImmutable();
        Element r_beta = Zr.newRandomElement().getImmutable();
        Element r_x = Zr.newRandomElement().getImmutable();
        Element r_delta1 = Zr.newRandomElement().getImmutable();
        Element r_delta2 = Zr.newRandomElement().getImmutable();
      // 生成零知识证明承诺R1-R5
        Element R1 = u.powZn(r_alpha).getImmutable(); // R₁ = u^{r_α}
        Element R2 = v.powZn(r_beta).getImmutable(); // R₂ = v^{r_β}
        Element R3Part1Pair = bp.pairing(T3,g2).getImmutable();// R₃复杂计算
        Element R3Part2Pair = bp.pairing(h,omega).getImmutable();
        Element R3Part3Pair = bp.pairing(h,g2).getImmutable();
        Element R3Part1 = R3Part1Pair.powZn(r_x);
        Element fu_r_alpha = r_alpha.negate().getImmutable();
        Element fu_r_beta = r_beta.negate().getImmutable();
//        System.out.println(r_alpha);
//        System.out.println(fu_r_alpha);//可以看出已经不是数论意义上的相反数了
//        System.out.println(fu_r_alpha.add(fu_r_beta));
//        System.out.println(fu_r_alpha.sub(r_beta));
        Element R3Part2 = R3Part2Pair.powZn(fu_r_alpha.add(fu_r_beta));
        Element R3Part3 = R3Part3Pair.powZn((r_delta1.negate()).sub(r_delta2));
        Element R3 = ((R3Part1.mul(R3Part2)).mul(R3Part3)).getImmutable();
        Element R4Part1 = T1.powZn(r_x);
        Element R4Part2 = u.powZn(r_delta1.negate());
        Element R4 = R4Part1.mul(R4Part2).getImmutable();
        Element R5Part1 = T2.powZn(r_x);
        Element R5Part2 = v.powZn(r_delta2.negate());
        Element R5 = R5Part1.mul(R5Part2).getImmutable();
       // 计算挑战值c （Fiat-Shamir启发式）
        String M="message";
        String M_sign = M + T1 + T2 + T3 + R1 + R2 + R3 + R4 + R5;
        int c_sign=M_sign.hashCode();
        byte[] c_sign_byte = Integer.toString(c_sign).getBytes();
        Element c = (Zr.newElementFromHash(c_sign_byte, 0, c_sign_byte.length)).getImmutable(); // 计算挑战值c
        //System.out.println(c);
        System.out.print("hash value c：");
        System.out.println(c);

        Element delta1 = x.mul(alpha).getImmutable();
        Element delta2 = x.mul(beta).getImmutable();
        Element s_alpha = r_alpha.add(c.mul(alpha)).getImmutable();
        Element s_beta = r_beta.add(c.mul(beta)).getImmutable();
        Element s_x = r_x.add(c.mul(x)).getImmutable();
        Element s_delta1 = r_delta1.add(c.mul(delta1)).getImmutable();
        Element s_delta2 = r_delta2.add(c.mul(delta2)).getImmutable();

        // 签名输出：
        System.out.println("\nsignature:");
        System.out.println("T1: " + T1);
        System.out.println("T2: " + T2);
        System.out.println("T3: " + T3);
        System.out.println("c: " + c);
        System.out.println("s_alpha: " + s_alpha);
        System.out.println("s_beta: " + s_beta);
        System.out.println("s_x: " + s_x);
        System.out.println("s_delta1: " + s_delta1);
        System.out.println("s_delta2: " + s_delta2);

        long endSign = System.nanoTime();
        long timeSign = endSign - startSign; //unit is nanosecond
        System.out.println("Signing time: "+timeSign/(1e6)+"ms");


        //4.Verification

        long startVerify = System.nanoTime();
        //4.Verification
        // 验证等式：R₁' = u^{s_α} · T₁^{-c}
        Element R1_barPart1 = u.powZn(s_alpha);
        Element R1_barPart2 = T1.powZn(c.negate());
        Element R1_bar = R1_barPart1.mul(R1_barPart2).getImmutable();
        //System.out.println(R1);
        //System.out.println(R1_bar);
        //System.out.println(R1_bar.isEqual(R1));
        Element R2_barPart1 = v.powZn(s_beta);
        Element R2_barPart2 = T2.powZn(c.negate());
        Element R2_bar = R2_barPart1.mul(R2_barPart2).getImmutable();
        //System.out.println(R2);
        //System.out.println(R2_bar);
        //System.out.println(R2_bar.isEqual(R2));
        Element R3_barPart1Pair = bp.pairing(T3,g2).getImmutable();
        Element R3_barPart2Pair = bp.pairing(h,omega).getImmutable();
        Element R3_barPart3Pair = bp.pairing(h,g2).getImmutable();
        Element R3_barPart1 = R3_barPart1Pair.powZn(s_x);
        Element R3_barPart2 = R3_barPart2Pair.powZn((s_alpha.negate()).sub(s_beta));
        Element fu_s_delta1 = s_delta1.negate().getImmutable();
        Element fu_s_delta2 = s_delta2.negate().getImmutable();
        Element R3_barPart3 = R3_barPart3Pair.powZn(fu_s_delta1.add(fu_s_delta2));
        Element e_T3_omega = bp.pairing(T3,omega).getImmutable();
        Element e_g1_g2 = bp.pairing(g1,g2).getImmutable();
        Element R3_barPart4 = (e_T3_omega.div(e_g1_g2)).powZn(c);
        Element R3_bar = R3_barPart1.mul(R3_barPart2).mul(R3_barPart3).mul(R3_barPart4).getImmutable();
        //System.out.println(R3);
        //System.out.println(R3_bar);
        //System.out.println(R3_bar.isEqual(R3));
        Element R4_barPart1 = T1.powZn(s_x);
        Element R4_barPart2 = u.powZn(fu_s_delta1);
        Element R4_bar = R4_barPart1.mul(R4_barPart2).getImmutable();
        //System.out.println(R4);
        //System.out.println(R4_bar);
        //System.out.println(R4_bar.isEqual(R4));
        Element R5_barPart1 = T2.powZn(s_x);
        Element R5_barPart2 = v.powZn(fu_s_delta2);
        Element R5_bar = R5_barPart1.mul(R5_barPart2).getImmutable();
        //System.out.println(R5);
        //System.out.println(R5_bar);
        //System.out.println(R5_bar.isEqual(R5));

        String M_verify=M;
        M_verify+=T1;
        M_verify+=T2;
        M_verify+=T3;
        M_verify+=R1_bar;
        M_verify+=R2_bar;
        M_verify+=R3_bar;
        M_verify+=R4_bar;
        M_verify+=R5_bar;
        int c_verify=M_verify.hashCode();
        byte[] c_verify_byte = Integer.toString(c_verify).getBytes();
        Element c_ = (Zr.newElementFromHash(c_verify_byte, 0, c_verify_byte.length)).getImmutable();
        System.out.print("hash value c_：");
        System.out.println(c_);
        //4.Verification 验证是否有效
        if(c_.isEqual(c)){   // ← 比较两个哈希值是否相等
            System.out.println("succeed to verify"); // 验证成功
        }
        else{
            System.out.println("fail to verify");  // 验证失败
        }

        long endVerify = System.nanoTime();
        long timeVerify = endVerify - startVerify; //unit is nanosecond
        System.out.println("Verification time: "+timeVerify/(1e6)+"ms");


        //5.Open the group signature to identify the signer
        long startOpen = System.nanoTime();
        Element A_ = T3.div((T1.powZn(xi_1)).mul(T2.powZn(xi_2)));// 追溯签名者
//        System.out.println(A);
//        System.out.println(A_);
        long endOpen = System.nanoTime();
        long timeOpen = endOpen - startOpen; //unit is nanosecond
        System.out.println("Open time: "+timeOpen/(1e6)+"ms");
    }
}
