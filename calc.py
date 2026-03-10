#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from cvss import CVSS3

def calculate_cvss_from_vector(vector):
    """
    Рассчитывает CVSS 3.1 по вектору атаки
    """
    try:
        # Создаём объект CVSS3
        c = CVSS3(vector)
        
        # Получаем все три оценки
        scores = c.scores()  # (base, temporal, environmental)
        severities = c.severities()  # (base_severity, temporal_severity, environmental_severity)
        
        # Очищенный вектор (без необязательных метрик)
        clean_vector = c.clean_vector()
        
        return {
            "vector_original": vector,
            "vector_clean": clean_vector,
            "base_score": scores[0],
            "base_severity": severities[0],
            "temporal_score": scores[1] if len(scores) > 1 else None,
            "temporal_severity": severities[1] if len(severities) > 1 else None,
            "environmental_score": scores[2] if len(scores) > 2 else None,
            "environmental_severity": severities[2] if len(severities) > 2 else None
        }
    except Exception as e:
        return {"error": str(e)}

def interactive_calculator():
    """
    Интерактивный режим калькулятора
    """
    print("\n" + "="*60)
    print("🧮 КАЛЬКУЛЯТОР CVSS 3.1")
    print("="*60)
    print("Формат вектора: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    print("(можно с префиксом CVSS:3.1 или без)")
    print("Для выхода введите 'exit'")
    print("-"*60)
    
    while True:
        vector = input("\nВведите вектор атаки: ").strip()
        
        if vector.lower() in ['exit', 'quit', 'q']:
            print("До свидания!")
            break
        
        if not vector:
            continue
        
        # Добавляем префикс, если его нет
        if not vector.startswith('CVSS:'):
            if vector.startswith('3.1/'):
                vector = 'CVSS:' + vector
            elif not vector.startswith('/'):
                vector = 'CVSS:3.1/' + vector
            else:
                vector = 'CVSS:3.1' + vector
        
        result = calculate_cvss_from_vector(vector)
        
        if "error" in result:
            print(f"❌ Ошибка: {result['error']}")
            print("Проверьте формат вектора")
        else:
            print("\n✅ РЕЗУЛЬТАТ:")
            print(f"   Вектор: {result['vector_clean']}")
            print(f"   Base Score: {result['base_score']:.1f} ({result['base_severity']})")
            if result['temporal_score']:
                print(f"   Temporal Score: {result['temporal_score']:.1f} ({result['temporal_severity']})")
            if result['environmental_score']:
                print(f"   Environmental Score: {result['environmental_score']:.1f} ({result['environmental_severity']})")

def main():
    if len(sys.argv) > 1:
        # Режим командной строки: python cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector = ' '.join(sys.argv[1:])
        result = calculate_cvss_from_vector(vector)
        if "error" in result:
            print(f"Ошибка: {result['error']}")
        else:
            print(f"Base Score: {result['base_score']:.1f} ({result['base_severity']})")
    else:
        # Интерактивный режим
        interactive_calculator()

if __name__ == "__main__":
    main()