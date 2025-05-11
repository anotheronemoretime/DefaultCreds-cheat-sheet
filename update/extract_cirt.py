import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

def extract_vendor_data(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        tables = soup.find_all('table')

        vendor_data = []
        
        for table in tables:
            first_row = table.find('tr')
            if not first_row:
                continue
                
            first_cell = first_row.find('td')
            if not first_cell:
                continue
                
            service_name = first_cell.text.strip()
            service_name = re.sub(r'^\d+\.\s+', '', service_name).split("-")[0].strip().replace(",", "")
            
            user_id = ""
            password = ""
            
            rows = table.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) >= 2:
                    field_name = cells[0].text.strip()
                    field_value = cells[1].text.strip()
                    
                    if "User ID" in field_name:
                        user_id = "" if field_value == "(none)" else field_value
                    elif "Password" in field_name:
                        password = "" if field_value == "(none)" else field_value
            
            if service_name:
                vendor_data.append({
                    'service': service_name,
                    'user_id': user_id,
                    'password': password
                })
            
        return vendor_data
    except Exception as e:
        print(f"Erreur lors de l'extraction des données de {url}: {e}")
        return []

def extract_vendor_urls():
    base_url = "https://cirt.net/passwords"
    
    try:
        response = requests.get(base_url)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        vendor_links = []
        
        for link in soup.find_all('a', href=True):
            if 'vendor=' in link['href']:
                full_url = urljoin(base_url, link['href'])
                vendor_links.append(full_url)
        
        for vendor_url in vendor_links:
            vendor_name = vendor_url.split('vendor=')[1]
            
            vendor_data = extract_vendor_data(vendor_url)
            
            if vendor_data:
                for data in vendor_data:
                    output = f"{data['service']}"
                    output += f",{data['user_id']}"  
                    output += f",{data['password']}" 
                    print(output)
        
    except requests.RequestException as e:
        print(f"Erreur lors de la récupération de la page : {e}")
    except Exception as e:
        print(f"Une erreur est survenue : {e}")

if __name__ == "__main__":
    extract_vendor_urls() 