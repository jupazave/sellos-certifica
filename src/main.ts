import './style.css';
import { vistaGenerar } from './ui/generar-view';
import { vistaValidar } from './ui/validar-view';

const app = document.querySelector<HTMLDivElement>('#app')!;

function render(vista: 'generar' | 'validar'): void {
  app.replaceChildren();

  const encabezado = document.createElement('header');
  encabezado.innerHTML = '<h1>Sellos — Generador de CSD</h1>';

  const nav = document.createElement('nav');
  const btnGenerar = document.createElement('button');
  btnGenerar.textContent = 'Generar CSD';
  btnGenerar.addEventListener('click', () => render('generar'));
  const btnValidar = document.createElement('button');
  btnValidar.textContent = 'Validar archivos';
  btnValidar.addEventListener('click', () => render('validar'));
  const btnLimpiar = document.createElement('button');
  btnLimpiar.textContent = 'Limpiar todo';
  btnLimpiar.title = 'Descarta todo lo cargado (recarga la página)';
  btnLimpiar.addEventListener('click', () => location.reload());
  nav.append(btnGenerar, btnValidar, btnLimpiar);

  app.append(encabezado, nav, vista === 'generar' ? vistaGenerar() : vistaValidar());
}

render('generar');
