import requests
from bs4 import BeautifulSoup
import webbrowser
from time import sleep
import random

session = requests.Session()

# Step 1: Get CSRF token and completeToken
get_url = "https://www.railway.gov.tw/tra-tip-web/tip/tip001/tip123/query"
get_response = session.get(get_url)
soup = BeautifulSoup(get_response.text, 'html.parser')

csrf_token = soup.find('input', {'name': '_csrf'})['value']
complete_token = soup.find('input', {'name': 'completeToken'})['value']

# Step 2: Prepare form data
post_url = "https://www.railway.gov.tw/tra-tip-web/tip/tip001/tip123/queryTrain"

form_data = [
    ("_csrf", csrf_token),
    ("custIdTypeEnum", "PERSON_ID"),
    ("pid", "B123291270"),  # 假身分證字號
    ("tripType", "ONEWAY"),
    ("orderType", "BY_TIME"),
    ("ticketOrderParamList[0].tripNo", "TRIP1"),
    ("ticketOrderParamList[0].startStation", "1210-新竹"),
    ("ticketOrderParamList[0].endStation", "1000-臺北"),
    ("ticketOrderParamList[0].rideDate", "2025/05/17"),
    ("ticketOrderParamList[0].startOrEndTime", "true"),
    ("ticketOrderParamList[0].startTime", "07:00"),
    ("ticketOrderParamList[0].endTime", "11:00"),
    ("ticketOrderParamList[0].normalQty", "2"),
    ("ticketOrderParamList[0].wheelChairQty", "0"),
    ("ticketOrderParamList[0].parentChildQty", "0"),
    # 車種選擇（1,2,3）
    ("ticketOrderParamList[0].trainTypeList", "1"),
    ("_ticketOrderParamList[0].trainTypeList", "on"),
    ("ticketOrderParamList[0].trainTypeList", "2"),
    ("_ticketOrderParamList[0].trainTypeList", "on"),
    ("ticketOrderParamList[0].trainTypeList", "3"),
    ("_ticketOrderParamList[0].trainTypeList", "on"),
    ("ticketOrderParamList[0].chgSeat", "true"),
    ("_ticketOrderParamList[0].chgSeat", "on"),
    ("ticketOrderParamList[0].seatPref", "NONE"),
    ("completeToken", complete_token)
]

# Step 3: Submit form
headers = {
    "Referer": get_url,
    "Origin": "https://www.railway.gov.tw",
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}


while(1):
    sleep(random.randint(5, 15)/10)
    response = session.post(post_url, headers=headers, data=form_data)

    # Step 4: Output result
    print(f"[+] HTTP {response.status_code}")
    # Count the number of <ul class='train-number'> directly in the response text
    # print(response.text)
    # exit()
    train_number_count = response.text.count("train-number")
    if(train_number_count != 0):
        print(f"[+] Found {train_number_count} train numbers")
        webbrowser.open(response.url)
        input()

# soup = BeautifulSoup(response.text, 'html.parser')


# if response.status_code == 200:
#     print(f"[+] Opening browser for URL: {response.url}")
#     webbrowser.open(response.url)

# 印出列車查詢結果摘要（以每列tr為單位）
# rows = soup.select("table tbody tr")
# print(f"[+] 找到 {len(rows)} 筆列車資訊")
# for row in rows[:5]:  # 只顯示前 5 筆
#     cols = [td.get_text(strip=True) for td in row.find_all("td")]
#     print(" | ".join(cols))
