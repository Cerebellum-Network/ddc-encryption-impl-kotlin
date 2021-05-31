package network.cere.ddc.crypto.v1.key.sign

import kotlin.experimental.and
import kotlin.experimental.xor

private val gf0: LongArray = LongArray(16) { 0 }
internal val gf1: LongArray = LongArray(16).apply { this[0] = 1 }
private val D: LongArray = longArrayOf(
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
)
private val I: LongArray = longArrayOf(
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
)

internal fun unpackneg(r: Array<LongArray>, p: ByteArray): Int {
    val t = LongArray(16)
    val chk = LongArray(16)
    val num = LongArray(16)
    val den = LongArray(16)
    val den2 = LongArray(16)
    val den4 = LongArray(16)
    val den6 = LongArray(16)
    set25519(r[2], gf1)
    unpack25519(r[1], p)
    S(num, r[1])
    M(den, num, D)
    Z(num, num, r[2])
    A(den, r[2], den)

    S(den2, den)
    S(den4, den2)
    M(den6, den4, den2)
    M(t, den6, num)
    M(t, t, den)

    pow2523(t, t)
    M(t, t, num)
    M(t, t, den)
    M(t, t, den)
    M(r[0], t, den)

    S(chk, r[0])
    M(chk, chk, den)
    if (neq25519(chk, num) != 0) {
        M(r[0], r[0], I)
    }

    S(chk, r[0])
    M(chk, chk, den)
    if (neq25519(chk, num) != 0) {
        return -1
    }

    if (par25519(r[0]) == ((p[31].toInt() shr 7) and 0xff).toByte()) {
        Z(r[0], gf0, r[0])
    }

    M(r[3], r[0], r[1])
    return 0
}

private fun set25519(r: LongArray, a: LongArray) {
    for (i in 0 until 16) r[i] = a[i]
}

private fun unpack25519(o: LongArray, n: ByteArray) {
    for (i in 0 until 16) {
        o[i] = (0xff and n[2 * i].toInt()) + (0xffL and n[2 * i + 1].toLong() shl 8)
    }
    o[15] = o[15] and 0x7fff
}

internal fun A(o: LongArray, a: LongArray, b: LongArray) {
    for (i in 0 until 16) o[i] = a[i] + b[i]
}

internal fun Z(o: LongArray, a: LongArray, b: LongArray) {
    for (i in 0 until 16) o[i] = a[i] - b[i]
}

internal fun M(o: LongArray, a: LongArray, b: LongArray) {
    val t = LongArray(31)

    for (i in 0 until 16) {
        for (j in 0 until 16) {
            t[i + j] += a[i] * b[j]
        }
    }
    for (i in 0 until 15) {
        t[i] += 38 * t[i + 16]
    }
    for (i in 0 until 16) {
        o[i] = t[i]
    }
    car25519(o)
    car25519(o)
}

private fun S(o: LongArray, a: LongArray) = M(o, a, a)

private fun pow2523(o: LongArray, i: LongArray) {
    val c = LongArray(16)
    for (a in 0 until 16) c[a] = i[a]
    for (a in 250 downTo 0) {
        S(c, c)
        if (a != 1) M(c, c, i)
    }
    for (a in 0 until 16) o[a] = c[a]
}

private fun neq25519(a: LongArray, b: LongArray): Int {
    val c = ByteArray(32)
    val d = ByteArray(32)
    pack25519(c, a)
    pack25519(d, b)
    return crypto_verify_32(c, 0, d, 0)
}

private fun par25519(a: LongArray): Byte {
    val d = ByteArray(32)
    pack25519(d, a)
    return (d[0] and 1)
}

private fun car25519(/*gf*/ o: LongArray, oOff: Int = 0) {
    for (i in 0 until 16) {
        o[oOff + i] += (1 shl 16).toLong()
        val c = o[oOff + i] shr 16
        o[oOff + (i + 1) * (if (i < 15) 1 else 0)] += c - 1 + 37 * (c - 1) * (if (i == 15) 1 else 0).toLong()
        o[oOff + i] -= c shl 16
    }
}

internal fun pack25519(o: ByteArray, n: LongArray, nOff: Int = 0) {
    var b: Int
    val m = LongArray(16)
    val t = LongArray(16)
    for (i in 0 until 16) t[i] = n[i + nOff]
    car25519(t)
    car25519(t)
    car25519(t)
    for (j in 0 until 2) {
        m[0] = t[0] - 0xffed
        for (i in 1 until 15) {
            m[i] = t[i] - 0xffff - ((m[i - 1] shr 16) and 1)
            m[i - 1] = m[i - 1] and 0xffff
        }
        m[15] = t[15] - 0x7fff - ((m[14] shr 16) and 1)
        b = ((m[15] shr 16) and 1).toInt()
        m[14] = m[14] and 0xffff
        sel25519(t, m, 1 - b)
    }
    for (i in 0 until 16) {
        o[2 * i] = t[i].toByte()
        o[2 * i + 1] = (t[i] shr 8).toByte()
    }
}

private fun crypto_verify_32(x: ByteArray, xi: Int = 0, y: ByteArray, yi: Int = 0): Int {
    return vn(x, xi, y, yi, 32)
}

private fun sel25519(p: LongArray, q: LongArray, b: Int) {
    var t: Long
    val c = (b - 1).inv().toLong()
    for (i in 0 until 16) {
        t = c and (p[i] xor q[i])
        p[i] = p[i] xor t
        q[i] = q[i] xor t
    }
}

private fun vn(x: ByteArray, xi: Int = 0, y: ByteArray, yi: Int, n: Int): Int {
    var d = 0
    for (i in 0 until n) {
        d = d or (0xff and (x[i + xi] xor y[i + yi]).toInt())
    }
    return ((1 and ((d - 1) shr 8)) - 1)
}

internal fun inv25519(o: LongArray, i: LongArray) {
    val c = LongArray(16)
    for (a in 0 until 16) c[a] = i[a]
    for (a in 253 downTo 0) {
        S(c, c)
        if (a != 2 && a != 4) M(c, c, i)
    }
    for (a in 0 until 16) o[a] = c[a]
}
