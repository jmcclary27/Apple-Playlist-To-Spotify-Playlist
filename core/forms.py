from django import forms

class LinkForm(forms.Form):
    url = forms.URLField(
        label='Paste your Apple Music playlist link',
        help_text='Example: https://music.apple.com/.../playlist/.../pl.xxxxx',
        widget=forms.URLInput(attrs={'placeholder': 'https://music.apple.com/...'})
    )
