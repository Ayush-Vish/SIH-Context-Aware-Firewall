import geoip2.database

geoip_db_path = "../GeoLite-database/GeoLite2-Country.mmdb"

def get_country(ip):
    reader = geoip2.database.Reader(geoip_db_path)
    
    try:
        response = reader.country(ip)
        country_code = response.country.iso_code  
        return country_code
    except geoip2.errors.AddressNotFoundError:
        return None
    finally:
        reader.close()

if __name__ == "__main__":
    ip_address = input("Enter IP address: ")
    country = get_country(ip_address)
    
    if country:
        print(f"The IP address {ip_address} belongs to {country}")
    else:
        print(f"Country not found for IP: {ip_address}")
