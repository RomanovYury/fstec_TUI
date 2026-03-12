import re
import json
import requests
from typing import Dict, Any, Optional
import urllib3
# Отключаем предупреждения о небезопасном соединении
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_vulnerability(url: str) -> Optional[Dict[str, Any]]:
    """
    Загружает страницу уязвимости по ID (например, '2026-02749')
    и возвращает структурированные данные.
    """
    #url = f"https://bdu.fstec.ru/vul/{bdu_id}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        # Добавляем параметр verify=False для отключения проверки сертификата
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка загрузки страницы: {e}")
        return {"vul_expl" : -1, 'vuln_incident': -1,'clv':{"clv_name" : "NaN"}}

    html = response.text
    vuln_data = extract_vuln_json(html)
    if vuln_data is None:
        print("Не удалось извлечь данные из страницы.")
        return {"vuln_expl" : -1, 'vuln_incident' : -1, 'clv' : {"clv_name":"NaN"}}
    return vuln_data

# Остальной код остается без изменений
def extract_vuln_json(html: str) -> Optional[Dict[str, Any]]:
    """
    Извлекает объект v_model из HTML страницы уязвимости.
    Возвращает словарь с данными или None, если не удалось найти.
    """
    # Ищем паттерн: v_model = reactive({...});
    # Внутри фигурных скобок может быть любой JSON, включая вложенные объекты.
    pattern = r'v_model\s*=\s*reactive\(({.*?})\);'
    match = re.search(pattern, html, re.DOTALL)
    if not match:
        return None
    json_str = match.group(1)
    try:
        data = json.loads(json_str)
        return data
    except json.JSONDecodeError:
        return None

if __name__ == "__main__":
    bdu_id = "2026-02800"  # можно подставить любой ID
    #data = fetch_vulnerability(bdu_id)
    data = fetch_vulnerability("https://bdu.fstec.ru/vul/2026-00827").get('vul_incident')
    print(data)
