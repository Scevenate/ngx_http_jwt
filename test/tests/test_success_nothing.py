from requests import Session

def test_success_nothing():
    with Session() as session:
        response = session.get("http://localhost:8080/robots.txt")
        assert response.content.decode() == "Don't scrape, thanks!"
