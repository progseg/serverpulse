from django.shortcuts import render

def terminal(request):
    return render(request, 'terminal.html')