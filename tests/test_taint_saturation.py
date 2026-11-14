#!/usr/bin/env python3
"""
test_taint_saturation.py

Test de saturation du FlowTracker de Cerbere-AG.

Objectif :
    Vérifier le comportement en cas de dépassement de _MAX_TRACKED (500).

Usage :
    python test_taint_saturation.py
"""

import random
import string
import sys
import time
from pathlib import Path

# Ajoute le dossier racine de cerbere-AG au PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentguard.taint import FlowTracker, TaintLevel


def generate_random_secret(length: int = 32) -> str:
    """Génère une chaîne aléatoire simulant un secret."""
    return "".join(
        random.choices(
            string.ascii_letters + string.digits,
            k=length,
        )
    )


def test_taint_saturation() -> None:
    """Teste la saturation du Taint Tracker."""

    print("=" * 80)
    print("TEST : Saturation du FlowTracker (DoS logique)")
    print("=" * 80)

    tracker = FlowTracker(
        session_mode=False,
        on_saturation="block",
    )

    print("\nConfiguration :")
    print(f"   - Tracker interne : {tracker._tracker.__class__.__name__}")
    print(f"   - Mode saturation : {tracker.on_saturation}")
    print("   - Needles max : 500 (valeur par défaut)")

    # Phase 1 : Remplissage progressif
    print("\nPhase 1 : Remplissage du tracker (0 → 600 needles)...")

    start_time = time.time()

    for needles_added, i in enumerate(range(600), start=1):
        secret = generate_random_secret()

        tracker.track(
            secret,
            source=f"source_{i}",
            level=TaintLevel.SECRET,
        )

        if needles_added % 50 == 0:
            report = tracker.report()

            print(
                f"   Ajouté {needles_added}/600 secrets | "
                f"Needles actifs : {report['tracked_needles']}"
            )

    fill_time = time.time() - start_time

    print(f"\nTemps de remplissage : {fill_time:.2f}s")

    # Phase 2 : Vérification de l'état
    print("\nPhase 2 : État du tracker après saturation")

    report = tracker.report()

    print(f"   - Needles actifs : {report['tracked_needles']}/500")
    print(f"   - Saturation détectée : {report['saturated']}")
    print(f"   - Needles évincés : {report['dropped_needles']}")
    print(f"   - Niveau de session : {report['session_level']}")

    # Phase 3 : Comportement post-saturation
    print("\nPhase 3 : Test de comportement post-saturation")

    # Test 1 : Payload bénin
    print("\nTest 1 : Envoi d'un payload bénin après saturation")

    benign_payload = "Rapport mensuel : ventes = 15000€, clients = 250"

    start_time = time.time()

    benign_label = tracker.level_in(
        benign_payload,
        external=True,
    )

    decision_time = time.time() - start_time

    print(f"   - Niveau détecté : {benign_label.level.name}")
    print(f"   - Source : {benign_label.source}")
    print(f"   - Temps de décision : {decision_time:.3f}s")

    if benign_label.level == TaintLevel.SECRET:
        print(
            "   RÉSULTAT : Payload bénin classé SECRET "
            "(faux positif potentiel)"
        )
    else:
        print("   RÉSULTAT : Payload non classé SECRET")

    # Test 2 : Véritable secret
    print("\nTest 2 : Envoi d'un vrai secret après saturation")

    real_secret = "sk-test-1234567890abcdefghijklmnop"

    start_time = time.time()

    secret_label = tracker.level_in(
        real_secret,
        external=True,
    )

    decision_time = time.time() - start_time

    print(f"   - Niveau détecté : {secret_label.level.name}")
    print(f"   - Source : {secret_label.source}")
    print(f"   - Temps de décision : {decision_time:.3f}s")

    if secret_label.level >= TaintLevel.SECRET:
        print("   RÉSULTAT : Secret correctement détecté")
    else:
        print("   RÉSULTAT : SECRET NON DÉTECTÉ")

    # Phase 4 : Réinitialisation
    print("\nPhase 4 : Test de clear()")

    tracker.clear()

    report_after_clear = tracker.report()

    print(
        f"   - Needles après clear : "
        f"{report_after_clear['tracked_needles']}"
    )
    print(
        f"   - Saturation après clear : "
        f"{report_after_clear['saturated']}"
    )

    clear_success = (
        report_after_clear["tracked_needles"] == 0
        and not report_after_clear["saturated"]
    )

    if clear_success:
        print("   RÉSULTAT : Clear() fonctionne correctement")
    else:
        print("   RÉSULTAT : Clear() n'a pas réinitialisé l'état")

    # Résumé final
    print(f"\n{'=' * 80}")
    print("RÉSUMÉ DU TEST")
    print(f"{'=' * 80}")

    vulnerabilities: list[str] = []

    if report["saturated"]:
        print("   Tracker arrivé à saturation")

        if report["dropped_needles"] > 0:
            print(
                f"   {report['dropped_needles']} needles évincés"
            )
            vulnerabilities.append(
                "Éviction de needles pendant la saturation"
            )

    if secret_label.level < TaintLevel.SECRET:
        vulnerabilities.append(
            "Secret non détecté après saturation"
        )

    if benign_label.level == TaintLevel.SECRET:
        vulnerabilities.append(
            "Faux positif : payload bénin classé SECRET"
        )

    if not clear_success:
        vulnerabilities.append(
            "Échec de la réinitialisation du tracker"
        )

    if not vulnerabilities:
        print("   Aucun problème détecté par ces vérifications")
    else:
        print("   Problèmes identifiés :")

        for vulnerability in vulnerabilities:
            print(f"   - {vulnerability}")

    print(
        "\nRecommandation : évaluer une politique LRU "
        "avec TTL pour les needles."
    )

    print(f"{'=' * 80}")


if __name__ == "__main__":
    test_taint_saturation()