from rest_framework.pagination import PageNumberPagination


# paginação de 20 objetos por página
class GenericPagination(PageNumberPagination):
    page_size = 20