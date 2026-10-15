import { useParams } from 'react-router-dom'
import { getGuideArea } from '../data/fieldGuide'
import GuideAreaPage from './GuideAreaPage'
import AcademyArticlePage from './AcademyArticlePage'

// /guide/:slug opens an area guide when the slug names one of the eight
// areas, otherwise the in-depth article with that slug (or an earlier alias).
export default function GuideEntryPage() {
  const { slug } = useParams()
  return getGuideArea(slug) ? <GuideAreaPage /> : <AcademyArticlePage />
}
