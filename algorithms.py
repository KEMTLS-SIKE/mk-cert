"""The algorithms in use"""
import itertools


# for legacy reasons, these are tuples,
# but both sides should be equal up to case.

signs = [
    ("dilithium2", "Dilithium2"),
    ("dilithium3", "Dilithium3"),
    ("dilithium5", "Dilithium5"),
    ("falcon512", "Falcon512"),
    ("falcon1024", "Falcon1024"),
    ("rainbowiclassic", "RainbowIClassic"),
    ("rainbowicircumzenithal", "RainbowICircumzenithal"),
    ("rainbowicompressed", "RainbowICompressed"),
    ("rainbowiiiclassic", "RainbowIiiClassic"),
    ("rainbowiiicircumzenithal", "RainbowIiiCircumzenithal"),
    ("rainbowiiicompressed", "RainbowIiiCompressed"),
    ("rainbowvclassic", "RainbowVClassic"),
    ("rainbowvcircumzenithal", "RainbowVCircumzenithal"),
    ("rainbowvcompressed", "RainbowVCompressed"),
    *[(sphincs.lower(), sphincs) for sphincs in (
        f"Sphincs{hash}{size}{fs}{kind}"
        for hash in ("Haraka", "Sha256", "Shake256")
        for size in ("128", "192", "256")
        for fs in ("f", "s")
        for kind in ("Simple", "Robust")
    )],
    ("xmss", "XMSS"),
]

kems = [
    ("kyber512", "Kyber512"),
    ("kyber768", "Kyber768"),
    ("kyber1024", "Kyber1024"),
    *[
        (f"classicmceliece{size}", f"ClassicMcEliece{size}")
        for size in (
            "348864",
            "348864f",
            "460896",
            "460896f",
            "6688128",
            "6688128f",
            "6960119",
            "6960119f",
            "8192128",
            "8192128f",
        )
    ],
    ("lightsaber", "Lightsaber"),
    ("saber", "Saber"),
    ("firesaber", "Firesaber"),
    ("ntruhps2048509", "NtruHps2048509"),
    ("ntruhps2048677", "NtruHps2048677"),
    ("ntruhps4096821", "NtruHps4096821"),
    ("ntruhrss701", "NtruHrss701"),
    ("ntruprimentrulpr653", "NtruPrimeNtrulpr653"),
    ("ntruprimentrulpr761", "NtruPrimeNtrulpr761"),
    ("ntruprimentrulpr857", "NtruPrimeNtrulpr857"),
    ("ntruprimesntrup653",  "NtruPrimeSntrup653"),
    ("ntruprimesntrup761",  "NtruPrimeSntrup761"),
    ("ntruprimesntrup857",  "NtruPrimeSntrup857"),
    *[
        (f"frodokem{size}{alg}{onecca}", f"FrodoKem{size.title()}{alg.title()}{onecca}")
        for size in ("640", "976", "1344")
        for alg in ("aes", "shake")
        for onecca in ("", "1CCA")
    ],
    *[
        (f"sikep{size}{compressed}{onecca.lower()}", f"SikeP{size}{compressed.title()}{onecca}")
        for size in ("434", "503", "610", "751")
        for compressed, onecca in (("", ""), ("compressed", ""), ("compressed", "1CCA"))
    ],
    ("csidhp512", "CsidhP512"),
    ("csidhp1024", "CsidhP1024"),
    ("bikel1", "BikeL1"),
    ("bikel3", "BikeL3"),
    *[(f"hqc{size}", f"Hqc{size}") for size in ["128", "192", "256"]],
]


oids = {definition[0]: i for (i, definition) in enumerate(itertools.chain(signs, kems), start=1)}


def get_oid(algorithm):
    oid = oids[algorithm]
    return f"1.3.6.1.4.1.44363.46.{oid}"


def get_oqs_id(algorithm):
    return dict(signs + [kem[:2] for kem in kems])[algorithm]


def is_sigalg(algorithm: str) -> bool:
    return algorithm.lower() in dict(signs).keys()