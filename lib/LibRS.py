from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from bplib import bp


class RS:

    def __init__(self):
        self.G = bp.BpGroup()
        self.p = int(self.G.order())
        self.n = -1
        
    def keygen(self, n):
        self.n = n
        x = Bn.from_decimal(str(self.p)).random()
        X = x * self.G.gen1()
        y = []
        Y = []
        _Y = []
        for i in range(n):
            y.append(Bn.from_decimal(str(self.p)).random())
            Y.append(y[i] * self.G.gen1())
            _Y.append(y[i] * self.G.gen2())
        Z = {}
        for i in range(n):
            for j in range(i):
                # Z[i * n + j] is Z(i, j), 0 < j < i
                Z[(i+1) * self.n + j+1] = (y[i] * y[j]) * self.G.gen1()
        sk = [x, y]
        vk = [X, Y, _Y, Z]
        return sk, vk

        
    def sign(self, sk, m):
        if self.n < 0:
            raise "RS::sign(): keygen should be runned before other functions"
        r = Bn.from_decimal(str(self.p)).random()
        sigma1 = r * self.G.gen2()
        e = sk[0]
        for i in range(self.n):
            e += sk[1][i] * m[i]
        sigma2 = e * sigma1
        return [bp.G1Elem.inf(self.G), bp.G1Elem.inf(self.G), sigma1, sigma2]


    def derive(self, vk, m, D, sigma):
        D = set(D)
        universal = set(range(1, self.n+1))
        D_ = universal - D

        t = Bn.from_decimal(str(self.p)).random()
        r = Bn.from_decimal(str(self.p)).random()
        sigma1_ = bp.G1Elem.inf(self.G)
        sigma2_ = bp.G1Elem.inf(self.G)
        if len(D_) != 0: # if _D_ is not empty 
            sigma1_ += t * self.G.gen1()
            for i in D_:
                sigma1_ += m[i-1] * vk[1][i-1]
            for i in D:
                sigma2_ += vk[1][i-1]
            sigma2_ = t * sigma2_
            for j in D_:
                temp_z = bp.G1Elem.inf(self.G)
                for i in D:
                    temp_z += vk[3][max(i, j) * self.n + min(i, j)]
                temp_z *= m[j-1]
                sigma2_ += temp_z
        else:
            sigma1_ = t * self.G.gen1()
            for i in range(self.n):
                sigma2_ += vk[1][i]
            sigma2_ *= t
        
        sigma1__ = r * sigma[2]
        sigma2__ = r * (sigma[3] + t * sigma[2])
        return [sigma1_, sigma2_, sigma1__, sigma2__]

    def verify(self, vk, sigma, m, D):
        expr1_1 = vk[0] + sigma[0]
        expr1_2 = bp.G2Elem.inf(self.G)
        for i in D:
            expr1_1 += m[i-1] * vk[1][i-1]
            expr1_2 += vk[2][i-1]
        expr2_1 = self.G.pair(expr1_1, sigma[2]) == self.G.pair(self.G.gen1(), sigma[3])
        expr2_2 = self.G.pair(sigma[0], expr1_2) == self.G.pair(sigma[1], self.G.gen2())
        # print(expr2_1)
        # print(expr2_2)
        return expr2_1 and expr2_2


# test
if __name__ == "__main__":
    m = [121, 234, 321, 541, 652, 960]
    D = set([1, 3, 4])
    # D = set([1, 2, 3, 4, 5, 6])

    rs = RS()
    sk, vk = rs.keygen(6)
    sigma = rs.sign(sk, m)
    sigma_d = rs.derive(vk, m, D, sigma)
    result = rs.verify(vk, sigma_d, m, D)
    print("result of Redactable Signatures: ", result)
