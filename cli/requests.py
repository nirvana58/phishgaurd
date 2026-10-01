import requests
from bs4 import BeautifulSoup

def decode_secret_message(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    rows = soup.find_all('tr')
    points = []
    max_x, max_y = 0, 0
    
    for row in rows:
        cols = row.find_all(['td', 'th'])
        if len(cols) == 3:
            x_text = cols[0].get_text(strip=True)
            char = cols[1].get_text()
            y_text = cols[2].get_text(strip=True)
            
            if not x_text.isdigit():
                continue
                
            x, y = int(x_text), int(y_text)
            points.append((x, y, char))
            max_x = max(max_x, x)
            max_y = max(max_y, y)
            
    grid = [[' ' for _ in range(max_x + 1)] for _ in range(max_y + 1)]
    for x, y, char in points:
        grid[y][x] = char
        
    for y in range(max_y, -1, -1):
        print("".join(grid[y]))