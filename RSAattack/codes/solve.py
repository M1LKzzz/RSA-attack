import math
import gmpy2
import libnum


def getOptions(filepath: str):
    with open(filepath, "r", encoding='GBK') as f:
        msg = f.read()
    n = int('0x' + msg[:1024 // 4], 16)
    e = int('0x' + msg[1024 // 4:2048 // 4], 16)
    c = int('0x' + msg[2048 // 4:], 16)
    return n, e, c


def getAllOptions():
    filepath = "../cryptodata/Frame"
    n = []
    e = []
    c = []
    for i in range(0, 21):
        n_temp, e_temp, c_temp = getOptions(filepath + str(i))
        n.append(n_temp)
        e.append(e_temp)
        c.append(c_temp)
    return n, e, c


def decryptRSA(p, q, e, c):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    print(libnum.n2s(int(pow(c, d, n)))[-8:])


def chinese_remainder_theorem(items):
    N = 1
    for a, n in items:
        N *= n
    result = 0
    for a, n in items:
        m = N // n
        r, s, d = extended_gcd(n, m)
        if d != 1:
            N = N // n
            continue
            # raise "Input not pairwise co-prime"
        result += a * s * m
    return result % N, N


def extended_gcd(a, b):
    x, y = 0, 1
    lastx, lasty = 1, 0
    while b:
        a, (q, b) = b, divmod(a, b)
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y
    return lastx, lasty, a


def com_module_attack(e1, e2, n, c1, c2):
    # a*e1 + b*e2 = 1
    a, b, d = extended_gcd(e1, e2)
    print('============frame0, frame4===================')
    print('p=')
    print('q=')
    print('frame0_e=' + str(e1))
    print('frame4_e=' + str(e2))
    print('msg=', end='')
    print(libnum.n2s(int((pow(c1, a, n) * pow(c2, b, n)) % n))[-8:])


def bad_choose_pq_com(e1, c1, n1, e2, c2, n2):
    p = math.gcd(n1, n2)
    q1 = n1 // p
    q2 = n2 // p
    print('================frame1======================')
    print('p=' + str(p))
    print('q=' + str(q1))
    print('e=' + str(e1))
    print('msg=', end='')
    decryptRSA(p, q1, e1, c1)
    print('================frame18======================')
    print('p=' + str(p))
    print('q=' + str(q2))
    print('e=' + str(e2))
    print('msg=', end='')
    decryptRSA(p, q2, e2, c2)


def broadcast_attack(params: list):
    x, n = chinese_remainder_theorem(params)
    print('==========frame3, 8, 12, 16, 20==============')
    print('p=')
    print('q=')
    print('e=5')
    print('msg=', end='')
    print(libnum.n2s(int(gmpy2.iroot(x, 5)[0]))[-8:])


def fermat(n):
    B = math.factorial(2 ** 14)
    v = 0
    i = 0
    t0 = gmpy2.iroot(n, 2)[0] + 1
    while i <= (B - 1):
        t = (t0 + i) * (t0 + i) - n
        if gmpy2.is_square(t):
            v = gmpy2.isqrt(t)
            break
        i = i + 1
    p = t0 + i + v
    q = n // p
    return p, q


def factor_n_fermat_attack(frames: list):
    i = 0
    for c, n, e in frames:
        if i == 0:
            print('================frame10======================')
        else:
            print('================frame14======================')
        p, q = fermat(n)
        print('p=' + str(p))
        print('q=' + str(q))
        print('e=' + str(e))
        print('msg=', end='')
        decryptRSA(p, q, e, c)
        i = i + 1


def factor_n_p_1(n):
    B = 2 ** 20
    a = 2
    d = 0
    for i in range(2, B + 1):
        a = pow(a, i, n)
        d = gmpy2.gcd(a - 1, n)
        if (d >= 2) and (d <= (n - 1)):
            q = n // d
            n = q * d
    return d


def factor_n_p_1_attack(frames: list):
    i = 0
    for c, n, e in frames:
        if i == 0:
            print('================frame2======================')
        elif i == 1:
            print('================frame6======================')
        else:
            print('================frame19======================')
        p = factor_n_p_1(n)
        q = n // p
        print('p=' + str(p))
        print('q=' + str(q))
        print('e=' + str(e))
        print('msg=', end='')
        decryptRSA(p, q, e, c)
        i = i + 1


if __name__ == '__main__':
    n, e, c = getAllOptions()
    # 通过getAllOptions来获得帧的参数

    # frame0, frame4为共模攻击
    com_module_attack(e[0], e[4], n[0], c[0], c[4])

    # frame1 frame18这两个的n有一个公因数
    bad_choose_pq_com(e[1], c[1], n[1], e[18], c[18], n[18])

    # frame3, 8, 12, 16, 20广播
    params = [(c[3], n[3])]
    params += [(c[8], n[8])]
    params += [(c[12], n[12])]
    params += [(c[16], n[16])]
    params += [(c[20], n[20])]
    broadcast_attack(params)

    # frame7,frame11, frame15, e = 3 ,尝试使用e = 5的破解方法没有成功
    # 参考博客说可以使用Coppersmith attack，由于格方面的知识不太会，准备之后学习格相关的知识再回来弄

    # frame2,frame6,frame19 --- p-1分解N
    frames = [(c[2], n[2], e[2])]
    frames += [(c[6], n[6], e[6])]
    frames += [(c[19], n[19], e[19])]
    factor_n_p_1_attack(frames)

    # frame10, 14 用fermat定理分解N
    frames = [(c[10], n[10], e[10]), (c[14], n[14], e[14])]
    factor_n_fermat_attack(frames)
