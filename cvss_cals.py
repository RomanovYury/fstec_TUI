from cvss import CVSS3,CVSS4,CVSS2
import numpy as np


def calc_cvss(vector):
    
    """Принимает вектор, возвращает словарь score - оценка в цифрах, lvl - оценка в словах""" 

    if vector != "Нет данных" and str(vector)!= "nan":
        if "CVSS:3.0" in vector or "CVSS:3.1" in vector:
            c = CVSS3(vector)
            
        elif "CVSS:4.0" in vector:
            c = CVSS4(vector)
           
        elif "CVSS:2.0" in vector: 
            c = CVSS2(vector)
            
        else:
            if "Au:" in vector: 
                c = CVSS2(vector)
                
            else:
                if "CVSS 3.0/" in vector:
                    vector = vector.replace("CVSS 3.0/", "CVSS:3.0/")
                c = CVSS3("CVSS:3.1/"+vector)
                
    else: 
        return {"score" : -1}
    
    return {"score" : c.scores()[0],"lvl" : c.severities()[0],}
   
