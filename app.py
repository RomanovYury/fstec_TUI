import os
import sys
import argparse
import pandas as pd
import numpy as np
from cvss_cals import calc_cvss 
#from bdu_parser import fetch_vulnerability


# ---------- Настройки по умолчанию ----------
# типы компонентов
TYPE_COEFF = {  
    "Важный компонент": 1.1,
    "Межсетевой экран": 0.9,
    "Сетевое устройство":0.9,
    "Телекомм. оборудование": 0.8,
    "Сервер": 0.7, 
    "АРМ" : 0.5,
    "СХД" : 0.4, 
    "Другое" : 0.1,
}
INTERNET_BONUS = 1.1          # множитель, если есть интернет
USE_LOG_QUANTITY = True       # учитывать количество через log(1+quantity)
DEFAULT_BASE_SCORE = 5.0      # базовая оценка, если в файле нет колонки с оценкой

# --------------------------------------------------------------



def load_file(filepath):
    if not os.path.exists(filepath):
        print(f"Ошибка: файл '{filepath}' не найден.")
        sys.exit(1)
    if filepath.endswith('.csv'):
        return pd.read_csv(filepath)
    else:
        return pd.read_excel(filepath)

def choose_column(df, prompt, default = None ): 
    print(f"\n{prompt} ")

    # вывод колонок 
    cols = list(df.columns)
    for i, col in enumerate(cols, 1):
        print(f"{i}. {col}")


    # ввод колонки 
    while True: 
        choice = input("Введите номер").strip()
        
        if choice.isdigit(): 
            idx = int(choice)
            if 1 <= idx <= len(cols):
                return cols[idx-1]
        print("Некорректный ввод, попробуйте снова.")


def get_unique_ips(df,ip_col):
    return df[ip_col].unique()


def interactive_input(unique_ips):
    data = [] 
    # список компонентов
    type_options = list(TYPE_COEFF.keys())
    ip_list = unique_ips.tolist()
    
    # ввод информации о хостах
    while len(ip_list) !=0 : 
        # вывод компонентов
        print("Выберите компонет:")
        for i, opt in enumerate(type_options, 1):
            print(f"  {i}. {opt}")
        t_choice = input("Введите номер: ")
        if t_choice.isdigit(): 
            num = int(t_choice)
            if 1<= num <= len(type_options): 
                typ = type_options[num-1]
            else: 
                print("Не верное число")
                continue 
        else: 
            print("Введите число")
            continue
        #----вывод компонентов

        #Ввод хостов по типу 
        count = 0
        while True: 
            print(f"Укажит хосты, которые являются {typ}\n")
            # вывод хостов
            print(f'Осталось {len(ip_list)} хостов')
            for i, ip in enumerate(ip_list,1): 
                print(f"{i}. {ip}")
            ip_choice = input("Введите номер: ")

            #выход назад
            if ip_choice == "-":
                if len(data) > 0 and count !=0 : 
                    while True: 
                        choice = input("Есть ли выход в интернет у хостов для данного компонента? [y/n]").strip()
                        if choice == "y":
                            choice_2 = input("Все ли хосты имеют выход в интернет? [y/n]")
                            if choice_2 == "y": 
                                for i in range(len(data)):
                                    if data[i]["Тип"] == typ: 
                                        data[i]["Интернет"] = 1
            
                            break
                            if choice_2 == "n": 
                                # потом допишу 
                                break
                        elif choice == "n":
                            for i in range(len(data)): 
                                if data[i]["Тип"] == typ: 
                                    data[i]["Интернет"] = 0
                            break
                        else: 
                            print("Непредвиденный вариант ответа")
                            continue

                #подсчет процентов
                for i in range(len(data)):
                    if data[i]["Тип"] == typ: 
                        data[i]["Процент"] = (count/len(unique_ips)) * 100 
                break
            #----выход назад


            # проверка на число
            
            if ip_choice.isdigit():
                num = int(ip_choice)
                if 1<= num <= (len(ip_list)): 
                    data.append(
                        {
                        "IP" : ip_list[num-1],
                        "Тип" : typ,
                        "Интернет" : "",
                        "Процент" : 100 
                        }
                    )
                    ip_list.pop(num-1)
                    count +=1 
                else:
                    print("Не верное число")
                    continue
            else: 
                print("Введите число")
                continue
         #---- проверка на число
         #----Ввод хостов по типу 

        #print(f"data : {data} \n ip_list: {ip_list}")    
    return data 

def calculate(row): 

    # ---------- Значение коэффициентов ----------
    k = 0.5 
    l = 0.2 
    p = 0.3 
    e = 1.0
    h = 1.0 
    # --------------------------------------------

    K = TYPE_COEFF[row["Тип"]]
    
    # расчет L 
    proc = row["Процент"]
    if proc > 70: 
        L = 1.0 
    elif 50 < proc <= 70:
        L = 0.8
    elif 10 <= proc < 50: 
        L = 0.6 
    elif proc < 10:
        L = 0.5
    else: 
        print(f"\t\tEROOR L: {row['Процент']}")
        exit(1) 
    # ---- расчет L 

    # расчет P 
    if row["Интернет"] == 1 : 
        P = 1.1
    elif row["Интернет"] == 0: 
        P = 0.6 
    else: 
        print(f"\t\tEROOR P: {row['Интернет']}")
        exit(1)
    # ---- расчет P 

    # расчет E  
    if row["ЭКСПЛОИТ"] == 0:
        E = 0.1 
    elif row["ЭКСПЛОИТ"] == 1 : 
        E = 0.6 ## !!!!!! 
    elif row["ЭКСПЛОИТ"] == 2:
        E = 0.6
    else:
        print(f"\t\tERROR E: {row["ЭКСПЛОИТ"]}")
        exit(1)
    # ---- расчет E 

    #расчет H 
    description = row["Описание БДУ"]
    if "произвольный код" in description.lower(): 
        H = 0.5
        type_H = "Выполнение произвольного кода (Arbitrary Code Execution)"
    elif "повысить свои привилегии" in description.lower(): 
        H = 0.5 
        type_H = "Повышение привилегий (Privilege Escalation)"
    elif "обойти существующие ограничения безопасности" in description.lower() or "обойти защитный механизм" in description.lower():
        H = 0.4
        type_H = "Обход механизмов безопасности (Security Bypass)"
    elif "внедрения кода" in description.lower():
        H = 0.34 
        type_H = "Внедрение кода (Code Injection)"
    elif "получить доступ к" in description.lower() or "раскрыть" in description.lower():
        H = 0.3
        type_H = "Получение конфиденциальной информации (Obtain Sensitive Information)"
    elif "нарушить" in description.lower():
        H = 0.3
        type_H = "Нарушение целостности данных (Loss of Integrity)"
    elif "отказ в обслуживании" in description.lower():
        H = 0.26
        type_H = "Отказ в обслуживании (DoS)"
    elif "перезапис" in description.lower():
        H = 0.22 
        type_H = "Перезапись произвольных файлов (Overwrite Arbitrary Files)"
    elif "запись локального файла" in description.lower():
        H = 0.2
        type_H = "Запись локальных файлов (Write Local Files)"
    elif "чтение локальных файлов" in description.lower():
        H = 0.18
        type_H = "Чтение локальных файлов (Read Local Files"
    elif "подмену пользовательского интерфейса" in description.lower():
        H = 0.12 
        type_H = "Поддельный пользовательский интерфейс"
    elif "межсай" in description.lower():
        H = 0.1
        type_H = "Межсайтовый скриптинг (Cross Site Scripting)"
    else:
        print(f"\t\tERROR H: {row["Описание БДУ"]}")
        H = -1 
        type_H = "НЕПРЕДВИДЕННЫЙ ТИП" 
    # ---- расчет H 

    Icvss = calc_cvss(row["Cvss Вектор"])['score']

    Iinfr = (k * k) + (l * L) + (p * P)  
    Iat = e * E
    Iimp = h * H 

    V = Icvss * Iinfr * (Iat + Iimp)

    # Добавление данных в таблицу
    row['k'] = k 
    row['K'] = K 
    row['l'] = l
    row['L'] = L
    row['p'] = p
    row['P'] = P
    row['e'] = e
    row['E'] = E
    row['h'] = h
    row["H"] = H 
    row['Iat'] = Iat
    row['Iimp'] = Iimp
    row['Iinfr'] = Iinfr
    row['Icvss'] = Icvss
    row["V"] = V
    row["Описание H"] = type_H
    # ---- Добавление данных в таблицу
    return row 

def save_report(df,default_name="report.csv"): 
    # вводим имя файла
    out_name = input(f"\nИмя файла для сохранения отчёта (по умолчанию {default_name}): ").strip()
    
    #проверка на дефолтное название 
    if not out_name:
        out_name = default_name
    if not out_name.endswith('.csv'):
        out_name += '.csv'
    df.to_csv(out_name, index=False, encoding='utf-8-sig')
    print(f"Отчёт сохранён как {out_name}")

def main():

    parser = argparse.ArgumentParser(description="Оценка критичности уязвимостей (консольная версия)")
    parser.add_argument("input_file", help="Путь к файлу с уязвимостями (CSV или Excel)")
    args = parser.parse_args()

    # загрузка файла
    print(f"Загрузка файла: {args.input_file}")
    df = load_file(args.input_file)
    print(f"Файл загружен. Строк: {len(df)}")
    print("\nПервые 5 строк:")
    print(df.head())


    # выбор колонки с хостами 
    ip_col = choose_column(df, "Выберите колонку с хостами:")

    # выбор колонки с вектором 
    vector_col = choose_column(df, "Выберите колонку с векторами:")

    #уникальные хосты 
    unique_ips = get_unique_ips(df,ip_col)

    # ввод информации о хостах 
    
    data = interactive_input(unique_ips)
    
    # for i in data: 
    #     print (f'{i}\n\n')

    print(data)

    #Объединение исходных данных с атрибутами
    merged = df.merge(pd.DataFrame(data), left_on=ip_col, right_on="IP", how="left")

    # подсчет всей информации
    

    calculate_colums = ['Iinfr', 'Iat', 'Iimp', 'k', 'K', 'l', 'L', 'p', 'P', 'e', 'E', 'h', 'H', 'V',"Описание H"]
    for col in calculate_colums:
        merged[col] = 'NaN' 

    data = merged.apply(lambda row: calculate(row), axis=1)

    save_report(data)


if __name__ == "__main__":
    main()




