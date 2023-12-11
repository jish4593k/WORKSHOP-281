import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base, Session
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

Base = declarative_base()

class WebForm(Base):
    __tablename__ = 'web_forms'
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String)
    method = Column(String)
    input_type = Column(String)
    input_name = Column(String)
    input_value = Column(String)

async def async_get_forms(url):
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        soup = BeautifulSoup(response.content, 'lxml')
        return soup.find_all('form')

def form_details(form):
    details_of_form = {}
    action = form.attrs.get('action')
    method = form.attrs.get('method', 'get')
    inputs = []

    for input_tag in form.find_all('input'):
        input_type = input_tag.attrs.get('type', 'text')
        input_name = input_tag.attrs.get('name')
        input_value = input_tag.attrs.get('value', '')
        inputs.append({
            'type': input_type,
            'name': input_name,
            'value': input_value,
        })

    details_of_form['action'] = action
    details_of_form['method'] = method
    details_of_form['inputs'] = inputs
    return details_of_form

def create_engine_sync():
    return create_engine('sqlite:///:memory:', echo=True)

async def create_engine_async():
    return create_async_engine('sqlite+aiosqlite:///:memory:', echo=True)

def create_tables(engine):
    Base.metadata.create_all(bind=engine)

async def store_web_form(session, form_details):
    web_form = WebForm(**form_details)
    session.add(web_form)
    await session.commit()

async def sql_injection_scan(url, session):
    forms = await async_get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)

        for i in "\"'":
            data = {}
            for input_tag in details['inputs']:
                if input_tag['type'] == 'hidden' or input_tag['value']:
                    data[input_tag['name']] = input_tag['value'] + i
                elif input_tag['type'] != 'submit':
                    data[input_tag['name']] = f'test{i}'

            if details['method'] == 'post':
                async with httpx.AsyncClient() as client:
                    response = await client.post(url, data=data)
            elif details['method'] == 'get':
                async with httpx.AsyncClient() as client:
                    response = await client.get(url, params=data)

            if vulnerable(response):
                print("SQL injection attack vulnerability in link:", url)
            else:
                print("No SQL injection attack vulnerability detected")
                break

async def main():
    url_to_be_checked = "https://cnn.com"

    # Use synchronous SQLAlchemy engine for creating tables
    sync_engine = create_engine_sync()
    create_tables(sync_engine)

    # Use asynchronous SQLAlchemy engine for storing web forms
    async_engine = await create_engine_async()
    async with AsyncSession(async_engine) as async_session:
        forms = await async_get_forms(url_to_be_checked)
        for form in forms:
            form_details_data = form_details(form)
            await store_web_form(async_session, form_details_data)

        # Run SQL injection scan
        await sql_injection_scan(url_to_be_checked, async_session)

def vulnerable(response):
    errors = {"quoted string not properly terminated",
              "unclosed quotation mark after the character string",
              "you have an error in your SQL syntax"
              }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
