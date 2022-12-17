/*
   YARA Rule Set
   Author: rverse_engineer
   Date: 2022-12-17
   Identifier: APT37_Lazarus_2022_Dec_1
   Reference: https://medium.com/@reverse_engineer/analysis-of-bluelight-trojan-c81cf74eb43b
*/

/* Rule Set ----------------------------------------------------------------- */

rule ceed3bfc1f8ab82bebee93db7300cfed5bdc17fddd0401b8addbb55f48bedff3 {
   meta:
      description = "APT37_Lazarus_2022_Dec_17_1"
      author = "rverse_engineer"
      reference = "https://medium.com/@reverse_engineer/analysis-of-bluelight-trojan-c81cf74eb43b"
      date = "2022-12-17"
      hash1 = "69631acda85439b0d6dbedcfdc90dc723350e1dae083db70afae5470c2d5b811"
   strings:
      $s1 = "ceed3bfc1f8ab82bebee93db7300cfed5bdc17fddd0401b8addbb55f48bedff3.exe" fullword ascii
      $s2 = "* e-9P" fullword ascii
      $s3 = "ceed3bfc1f8ab82bebee93db7300cfed5bdc17fddd0401b8addbb55f48bedff3" ascii
      $s4 = "A-/. -" fullword ascii
      $s5 = "SJ%G%_l" fullword ascii
      $s6 = "KaKc\\l" fullword ascii
      $s7 = "UnGW\"Zo!M" fullword ascii
      $s8 = "UDaI\\>" fullword ascii
      $s9 = ")BgfmsPS" fullword ascii
      $s10 = "QzhuNDx" fullword ascii
      $s11 = "Ok.uUd@" fullword ascii
      $s12 = "4}PIEaPz@3[." fullword ascii
      $s13 = "l^EzMz$7Ek" fullword ascii
      $s14 = "fooljKT" fullword ascii
      $s15 = "LlosO\"D1" fullword ascii
      $s16 = "bmwW)zW" fullword ascii
      $s17 = "SmdNOh>" fullword ascii
      $s18 = "ksJuHC'" fullword ascii
      $s19 = "ourd\"\"" fullword ascii
      $s20 = "EkiQ^,\\" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule e32c5d851cf23a6d3ecd224055619996d32210cc198ccd770494a902c788b481 {
   meta:
      description = "APT37_Lazarus_2022_Dec_17_2"
      author = "rverse_engineer"
      reference = "https://medium.com/@reverse_engineer/analysis-of-bluelight-trojan-c81cf74eb43b"
      date = "2022-12-17"
      hash1 = "e34078575aa5bbeaa681a18b9a22c2df0f97f72a1ac7c096d89b0c48c0156a30"
   strings:
      $s1 = "e32c5d851cf23a6d3ecd224055619996d32210cc198ccd770494a902c788b481.exe" fullword ascii
      $s2 = "ROkc%K%~" fullword ascii
      $s3 = ",Q:\\Z4" fullword ascii
      $s4 = ",%u%!2yC0N" fullword ascii
      $s5 = "khqafi" fullword ascii
      $s6 = "eYrWk54" fullword ascii
      $s7 = "rtHPPt4" fullword ascii
      $s8 = "YlYc~Hq" fullword ascii
      $s9 = "rKLN/7\\M" fullword ascii
      $s10 = "xwwWbgw" fullword ascii
      $s11 = "JwPzF*2" fullword ascii
      $s12 = "YAWB+2Q{L " fullword ascii
      $s13 = "Pkiz)quh" fullword ascii
      $s14 = "*)'KlahQ0~@&" fullword ascii
      $s15 = "wJXjXRcH" fullword ascii
      $s16 = "WcxClE/" fullword ascii
      $s17 = "RB1YpBr|Xd" fullword ascii
      $s18 = "yRLb*f;" fullword ascii
      $s19 = "numTf?" fullword ascii
      $s20 = "]KAIXD UB" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule sig_6f0feaba669466640fc87b77b7e64cf719644fed348b4faa015a2ffd467e8c41 {
   meta:
      description = "APT37_Lazarus_2022_Dec_17_3"
      author = "rverse_engineer"
      reference = "https://medium.com/@reverse_engineer/analysis-of-bluelight-trojan-c81cf74eb43b"
      date = "2022-12-17"
      hash1 = "c226696d0da307d97a6a62a58aa0d078ea9c0f5291afeb52d0e98a2a21a569e6"
   strings:
      $s1 = "6f0feaba669466640fc87b77b7e64cf719644fed348b4faa015a2ffd467e8c41.exe" fullword ascii
      $s2 = "HGQ.XMk" fullword ascii
      $s3 = "6f0feaba669466640fc87b77b7e64cf719644fed348b4faa015a2ffd467e8c41" ascii
      $s4 = "'XE* ]" fullword ascii
      $s5 = "K`V* M" fullword ascii
      $s6 = "BsNSCsQ" fullword ascii
      $s7 = "wvYtc(z&" fullword ascii
      $s8 = "ywghUn s" fullword ascii
      $s9 = "zXaE k={" fullword ascii
      $s10 = "#<iBPlEOa" fullword ascii
      $s11 = ";.znP;" fullword ascii
      $s12 = "DkMqg%>" fullword ascii
      $s13 = "EZWah?" fullword ascii
      $s14 = "clDZv\"" fullword ascii
      $s15 = "XnNDsb,-F" fullword ascii
      $s16 = "$KMKOYb~" fullword ascii
      $s17 = "FGTae+l" fullword ascii
      $s18 = "b\\.VSm," fullword ascii
      $s19 = "EUSS'1\"" fullword ascii
      $s20 = "8OJnIVzbu" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}
