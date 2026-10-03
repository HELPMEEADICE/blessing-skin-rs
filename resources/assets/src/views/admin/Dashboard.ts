import { get } from '../../scripts/net'
import { createDashboardChart } from './createDashboardChart'

interface ChartData {
  labels: string[]
  xAxis: string[]
  data: number[][]
}

async function main() {
  if (document.querySelector('#admin-dashboard-app')) {
    return
  }
  const elUsersRegistration = document.querySelector<HTMLDivElement>(
    '#chart-users-registration',
  )
  const elTexturesUpload = document.querySelector<HTMLDivElement>(
    '#chart-textures-upload',
  )
  if (!elUsersRegistration || !elTexturesUpload) {
    return
  }

  const isDarkMode = document.body.classList.contains('dark-mode')
  const textColor = isDarkMode ? '#fff' : '#000'

  const chartData: ChartData = await get('/admin/chart')
  createDashboardChart(
    elUsersRegistration,
    isDarkMode ? '#3498db' : '#17a2b8',
    textColor,
    {
      label: chartData.labels[0]!,
      xAxis: chartData.xAxis,
      data: chartData.data[0]!,
    },
  )
  createDashboardChart(elTexturesUpload, '#6f42c1', textColor, {
    label: chartData.labels[1]!,
    xAxis: chartData.xAxis,
    data: chartData.data[1]!,
  })
}

main()
