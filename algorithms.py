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
    ("kyber512", "Kyber512", False),
    ("kyber768", "Kyber768", False),
    ("kyber1024", "Kyber1024", False),
    *[
        (f"classicmceliece{size}", f"ClassicMcEliece{size}", False)
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
    ("lightsaber", "Lightsaber", False),
    ("saber", "Saber", False),
    ("firesaber", "Firesaber", False),
    ("ntruhps2048509", "NtruHps2048509", False),
    ("ntruhps2048677", "NtruHps2048677", False),
    ("ntruhps4096821", "NtruHps4096821", False),
    ("ntruhrss701", "NtruHrss701", False),
    ("ntruprimentrulpr653", "NtruPrimeNtrulpr653", False),
    ("ntruprimentrulpr761", "NtruPrimeNtrulpr761", False),
    ("ntruprimentrulpr857", "NtruPrimeNtrulpr857", False),
    ("ntruprimesntrup653",  "NtruPrimeSntrup653", False),
    ("ntruprimesntrup761",  "NtruPrimeSntrup761", False),
    ("ntruprimesntrup857",  "NtruPrimeSntrup857", False),
    *[
        (f"frodokem{size}{alg}", f"FrodoKem{size.title()}{alg.title()}", False)
        for size in ("640", "976", "1344")
        for alg in ("aes", "shake")
    ],
    *[
        (f"sikep{size}{compressed}{'async' if asynchronous else ''}", f"SikeP{size}{compressed.title()}", asynchronous)
        for size in ("434", "503", "610", "751")
        for (compressed, asynchronous) in (("", False), ("compressed", False), ("compressed", True))
    ],
    ("bikel1", "BikeL1", False),
    ("bikel3", "BikeL3", False),
    *[(f"hqc{size}", f"Hqc{size}", False) for size in ["128", "192", "256"]],
]


oids = {definition[0]: i for (i, definition) in enumerate(itertools.chain(signs, kems), start=1)}


def get_oid(algorithm):
    oid = oids[algorithm]
    return f"1.3.6.1.4.1.44363.46.{oid}"


def get_oqs_id(algorithm):
    return dict(signs + [kem[:2] for kem in kems])[algorithm]


def is_sigalg(algorithm: str) -> bool:
    return algorithm.lower() in dict(signs).keys()