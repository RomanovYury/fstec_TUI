from cvss import CVSS3



def calc_cvss(vector):
    
    """Принимает вектор, возвращает словарь score - оценка в цифрах, lvl - оценка в словах""" 


    c = CVSS3(vector)
    #print(c.scores()[0])
    #print(c.severities()[0])
    
    return {"score" : c.scores()[0],"lvl" : c.severities()[0],}
    




