#python fileSafetyCheck.py
#821c7d971d26bff91665027e1947212bc34cf7d671acf7382b91730444ac6219
import json
import requests

def safety_check(file):

    url = "https://www.virustotal.com/api/v3/files"
    file_path = file

    files = {"file": (file_path, open(file_path, "rb"), "text/plain")}
    headers = {
        "accept": "application/json",
        "x-apikey": "821c7d971d26bff91665027e1947212bc34cf7d671acf7382b91730444ac6219"
    }

    response = requests.post(url, files=files, headers=headers)

    try:
        # Используйте response.json() для получения JSON-данных из ответа
        data = response.json()

        # Извлечение значения "id"
        analysis_id = data.get("data", {}).get("id")

        if analysis_id:
            process_id = analysis_id
        else:
            return ("ID не найден в данных.")
    except json.JSONDecodeError as e:
        return (f"Ошибка при декодировании JSON: {e}")
    except Exception as e:
        return (f"Произошла ошибка: {e}")


    url = f"https://www.virustotal.com/api/v3/analyses/{process_id}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": "821c7d971d26bff91665027e1947212bc34cf7d671acf7382b91730444ac6219"
    }

    response = requests.get(url, headers=headers)


    data = response.json()

    categories = [result["category"] for result in data["data"]["attributes"]["results"].values()]

    if categories.count('detected') > 1:
        return False
    else:
        return True