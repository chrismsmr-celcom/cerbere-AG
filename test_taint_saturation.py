#!/usr/bin/env python3
"""
test_taint_saturation.py
Test de saturation du FlowTracker de Cerbere-AG
Objectif : Vérifier le comportement en cas de dépassement de _MAX_TRACKED (500)
"""

import sys
import os
import random
import string
import time

# Ajoute le chemin du repo au PYTHONPATH
sys.path.insert(0, '/path/to/cerbere-AG')

from agentguard.taint import FlowTracker, TaintLevel

def generate_random_secret(length=32):
    """Génère une chaîne aléatoire simulant un secret"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def test_taint_saturation():
    """
    Test de saturation du Taint Tracker
    """
    print("=" * 80)
    print("🧪 TEST : Saturation du FlowTracker (DoS logique)")
    print("=" * 80)
    
    # Créer un tracker avec mode "block" (défaut)
    tracker = FlowTracker(session_mode=False, on_saturation="block")
    
    print(f"\n📊 Configuration :")
    print(f"   - _MAX_TRACKED : {tracker._tracker.__class__.__name__}")
    print(f"   - Mode saturation : {tracker.on_saturation}")
    print(f"   - Needles max : 500 (valeur par défaut)")
    
    # Phase 1 : Remplir progressivement le tracker
    print(f"\n🔄 Phase 1 : Remplissage du tracker (0 → 500 needles)...")
    
    needles_added = 0
    start_time = time.time()
    
    for i in range(600):  # Tente d'ajouter 600 secrets (plus que la limite)
        secret = generate_random_secret()
        
        # Simule un secret entrant dans le contexte de l'agent
        tracker.track(secret, source=f"source_{i}", level=TaintLevel.SECRET)
        
        needles_added += 1
        
        # Log tous les 50 secrets
        if needles_added % 50 == 0:
            report = tracker.report()
            print(f"   ✅ Ajouté {needles_added}/600 secrets | Needles actifs : {report['tracked_needles']}")
    
    fill_time = time.time() - start_time
    print(f"\n⏱️  Temps de remplissage : {fill_time:.2f}s")
    
    # Phase 2 : Vérifier l'état du tracker
    print(f"\n📊 Phase 2 : État du tracker après saturation")
    report = tracker.report()
    
    print(f"   - Needles actifs : {report['tracked_needles']}/500")
    print(f"   - Saturation détectée : {report['saturated']}")
    print(f"   - Needles évincés : {report['dropped_needles']}")
    print(f"   - Niveau de session : {report['session_level']}")
    
    # Phase 3 : Tester le comportement post-saturation
    print(f"\n🧪 Phase 3 : Test de comportement post-saturation")
    
    # Tentative 1 : Envoyer un payload légitime (non malveillant)
    print(f"\n   🔵 Test 1 : Envoi d'un payload bénin après saturation")
    benign_payload = "Rapport mensuel : ventes = 15000€, clients = 250"
    
    start_time = time.time()
    label = tracker.level_in(benign_payload, external=True)
    decision_time = time.time() - start_time
    
    print(f"   - Niveau détecté : {label.level.name}")
    print(f"   - Source : {label.source}")
    print(f"   - Temps de décision : {decision_time:.3f}s")
    
    if label.level == TaintLevel.SECRET:
        print(f"   ⚠️  RÉSULTAT : Le tracker est en mode 'block' → payload bénin bloqué (faux positif)")
    else:
        print(f"   ✅ RÉSULTAT : Payload autorisé")
    
    # Tentative 2 : Envoyer un vrai secret
    print(f"\n   🔴 Test 2 : Envoi d'un vrai secret après saturation")
    real_secret = "sk-test-1234567890abcdefghijklmnop"
    
    start_time = time.time()
    label = tracker.level_in(real_secret, external=True)
    decision_time = time.time() - start_time
    
    print(f"   - Niveau détecté : {label.level.name}")
    print(f"   - Source : {label.source}")
    print(f"   - Temps de décision : {decision_time:.3f}s")
    
    if label.level >= TaintLevel.SECRET:
        print(f"   ✅ RÉSULTAT : Secret correctement bloqué")
    else:
        print(f"   ❌ RÉSULTAT : SECRET NON DÉTECTÉ → faille critique !")
    
    # Phase 4 : Test de clear()
    print(f"\n🧹 Phase 4 : Test de clear() (réinitialisation)")
    
    tracker.clear()
    report_after_clear = tracker.report()
    
    print(f"   - Needles après clear : {report_after_clear['tracked_needles']}")
    print(f"   - Saturation après clear : {report_after_clear['saturated']}")
    
    if report_after_clear['tracked_needles'] == 0 and not report_after_clear['saturated']:
        print(f"   ✅ RÉSULTAT : Clear() fonctionne correctement")
    else:
        print(f"   ❌ RÉSULTAT : Clear() n'a pas réinitialisé l'état")
    
    # Résumé final
    print(f"\n{'=' * 80}")
    print(f"📋 RÉSUMÉ DU TEST")
    print(f"{'=' * 80}")
    
    vulnerabilities = []
    
    if report['saturated']:
        print(f"⚠️  Le tracker a atteint la saturation")
        
        if report['dropped_needles'] > 0:
            print(f"⚠️  {report['dropped_needles']} needles ont été évincés (perte de suivi)")
            vulnerabilities.append("Éviction de needles sans LRU explicite")
    
    if label.level < TaintLevel.SECRET and real_secret in benign_payload:
        vulnerabilities.append("Secret non détecté après saturation")
    
    if not vulnerabilities:
        print(f"✅ Aucun problème critique détecté")
        print(f"ℹ️  Le tracker fonctionne correctement mais reste limité à 500 needles")
    else:
        print(f"❌ Problèmes identifiés :")
        for vuln in vulnerabilities:
            print(f"   - {vuln}")
    
    print(f"\n💡 Recommandation : Implémenter une politique LRU avec TTL pour les needles")
    print(f"{'=' * 80}")

if __name__ == "__main__":
    test_taint_saturation()