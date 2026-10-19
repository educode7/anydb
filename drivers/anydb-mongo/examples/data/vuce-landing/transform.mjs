// Derives the seed documents from the verbatim upstream payload.
//
//   node transform.mjs        # rewrites group-*.json next to this file
//
// Source: https://gateway-apim.vuce.gob.pe/pass-through-https/autenticacion2/landing-componentes/1.0/aplicaciones
// (committed verbatim as aplicaciones.json).
//
// Two independent rewrites happen here, and nothing else changes:
//
// 1. Scalar shape. The consumer entities declare these fields as String
//    (`ComponentsEntity.isActive`, `ComponentEntity.codeComponent`,
//    `ComponentEntity.hasModal`), and the repository reads with
//    `findByIsActiveEquals("1")` — a STRING query. The payload carries
//    group `isActive: 1`, component `codeComponent: 1` and boolean
//    `hasModal`, so each is stringified to "1", "1" and "true"/"false".
//
// 2. authenticationType (the requested rules, verbatim):
//      - modal option titled "Mercancías Restringidas"      -> AUTH1_AUTH2
//      - modal option titled "Mercancías Restringidas - IPEN" -> AUTH2
//      - the component owning that first option ("la principal") -> AUTH1_AUTH2
//      - modal option titled "Gestión de Naves 2.0"          -> AUTH2
//      - every other component and every other modal option  -> AUTH1
//
// The assertions at the bottom fail the process if any of those rules
// stops holding, so a regrouped payload can never seed silently wrong
// data.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const payload = JSON.parse(readFileSync(join(here, 'aplicaciones.json'), 'utf8'));

const AUTH1 = 'AUTH1';
const AUTH1_AUTH2 = 'AUTH1_AUTH2';
const AUTH2 = 'AUTH2';

// Modal option titles with an explicitly requested type; the default
// for everything else is AUTH1.
const OPTION_TYPES = new Map([
  ['Mercancías Restringidas', AUTH1_AUTH2],
  ['Mercancías Restringidas - IPEN', AUTH2],
  ['Gestión de Naves 2.0', AUTH2],
]);

const counts = (texts) =>
  texts.reduce(
    (acc, text) => ({ ...acc, [text]: (acc[text] ?? 0) + 1 }),
    {},
  );

const groups = payload.groups.map((group, index) => {
  const document = {
    ...group,
    isActive: String(group.isActive),
    listComponent: group.listComponent.map((component) => {
      const modalOptions = Array.isArray(component.modalOptions)
        ? component.modalOptions.map((option) => ({
            ...option,
            authenticationType: OPTION_TYPES.get(option.title) ?? AUTH1,
          }))
        : component.modalOptions;
      const titles = (modalOptions ?? []).map((option) => option.title);
      return {
        ...component,
        codeComponent: String(component.codeComponent),
        hasModal: String(component.hasModal),
        authenticationType: titles.includes('Mercancías Restringidas')
          ? AUTH1_AUTH2
          : AUTH1,
        modalOptions,
      };
    }),
  };
  const name = `group-${index + 1}.json`;
  writeFileSync(join(here, name), `${JSON.stringify(document, null, 2)}\n`);
  console.log(`${name}: ${document.listComponent.length} component(s)`);
  return document;
});

// ---------- assertions: the rules above, checked ---------------------
const fail = (message) => {
  throw new Error(`transform: ${message}`);
};

if (groups.length !== 3) fail(`expected 3 groups, got ${groups.length}`);
for (const group of groups) {
  if (group.isActive !== '1') fail(`group ${group.codeGroup} isActive is ${JSON.stringify(group.isActive)}`);
  for (const component of group.listComponent) {
    if (typeof component.codeComponent !== 'string') fail(`codeComponent of ${component.name} is not a string`);
    if (typeof component.hasModal !== 'string') fail(`hasModal of ${component.name} is not a string`);
    if (component.authenticationType === null || component.authenticationType === undefined) {
      fail(`component ${component.name} has no authenticationType`);
    }
    if (component.authenticationType !== AUTH1 && component.authenticationType !== AUTH1_AUTH2) {
      fail(`component ${component.name} has unexpected type ${component.authenticationType}`);
    }
    for (const option of component.modalOptions ?? []) {
      if (option.authenticationType === null || option.authenticationType === undefined) {
        fail(`modal option ${option.title} has no authenticationType`);
      }
    }
  }
}

const group1 = groups.find((group) => group.codeGroup === '1');
const restricted = group1.listComponent.find((component) => component.codeComponent === '1');
if (restricted.authenticationType !== AUTH1_AUTH2) {
  fail(`the principal Mercancías Restringidas component must be ${AUTH1_AUTH2}, got ${restricted.authenticationType}`);
}
const optionType = (component, title) =>
  (component.modalOptions ?? []).find((option) => option.title === title)?.authenticationType;
if (optionType(restricted, 'Mercancías Restringidas') !== AUTH1_AUTH2) fail('modal "Mercancías Restringidas" must be AUTH1_AUTH2');
if (optionType(restricted, 'Mercancías Restringidas - IPEN') !== AUTH2) fail('modal "Mercancías Restringidas - IPEN" must be AUTH2');

const naves = group1.listComponent.find((component) => component.codeComponent === '5');
if (optionType(naves, 'Gestión de Naves 2.0') !== AUTH2) fail('modal "Gestión de Naves 2.0" must be AUTH2');
if (optionType(naves, 'Gestión de Naves') !== AUTH1) fail('modal "Gestión de Naves" defaults to AUTH1');
if (naves.authenticationType !== AUTH1) fail('the parent of Gestión de Naves defaults to AUTH1');

const options = groups.flatMap((group) =>
  group.listComponent.flatMap((component) =>
    (component.modalOptions ?? []).map((option) => option.authenticationType),
  ),
);
const components = groups.flatMap((group) => group.listComponent.map((component) => component.authenticationType));
console.log(`components: ${JSON.stringify(counts(components))}`);
console.log(`modalOptions: ${JSON.stringify(counts(options))}`);
