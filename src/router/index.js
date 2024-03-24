import {createRouter, createWebHashHistory} from 'vue-router'
import Dns from '../views/DnsPage.vue'

const routes = [
    {
        path: '/',
        name: 'Dns',
        component: Dns
    }
]

const router = createRouter({
    history: createWebHashHistory(),
    routes
})

export default router
