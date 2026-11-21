import { createContext, useContext } from 'react'

export const PanelContext = createContext({
  openIssue: () => {},
  openCategory: () => {},
  openSubdomain: () => {},
})

export const CatalogContext = createContext({ rules: {}, categories: {} })

export const usePanels = () => useContext(PanelContext)
export const useCatalog = () => useContext(CatalogContext)
